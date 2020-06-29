using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    public class Scp11Context : Context
    {
        public static Span<byte> X963Kdf(IDigest digest, ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, int length)
        {
            var size = digest.GetDigestSize();
            var cnt = 0U;
            var ms = new MemoryStream();
            ms.Write(shsee);
            ms.Write(shsss);
            ms.Write(cnt);
            var buf = ms.AsSpan();
            var cspan = buf.Slice(buf.Length - 4);
            var ret = new byte[size * ((length + size - 1) / size)];
            for (var offs = 0; offs < length; offs += size)
            {
                BinaryPrimitives.WriteUInt32BigEndian(cspan, ++cnt);
                digest.Reset();
                digest.BlockUpdate(buf);
                digest.DoFinal(ret, offs);
            }
            return ret.AsSpan(0, length);
        }

        public Span<byte> CalculateShs(ReadOnlySpan<byte> shsee, int length)
        {
            return X963Kdf(new Sha256Digest(), shsee, shsss, length);
        }

        public ECPublicKeyParameters DecodePoint(ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(bytes), domain);
        }

        public Scp11Context(Session session)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);

            generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));

            pk_sd = DecodePoint(session.SendCmd(HsmCommand.GetDevicePubKey));

            var factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, "/usr/local/lib/libykcs11.dylib", AppType.SingleThreaded))
            {
                foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                {
                    using (var s = slot.OpenSession(SessionType.ReadWrite))
                    {
                        s.Login(CKU.CKU_USER, "123456");

                        var keys = s.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 256) });

                        if (keys.Count > 0)
                        {
                            var bytes = s.GetAttributeValue(keys[0], new List<CKA> { CKA.CKA_EC_POINT })[0].GetValueAsByteArray();
                            var octets = (Asn1OctetString)Asn1Object.FromByteArray(bytes);
                            X9ECPoint point = new X9ECPoint(domain.Curve, octets);
                            pk_oce = new ECPublicKeyParameters(point.Point, domain);

                            var mech = factories.MechanismFactory.Create(CKM.CKM_ECDH1_DERIVE,
                                factories.MechanismParamsFactory.CreateCkEcdh1DeriveParams((ulong)CKD.CKD_NULL, null, pk_sd.Q.GetEncoded()));

                            var obj = s.DeriveKey(mech, keys[0], new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET) });

                            var v = s.GetAttributeValue(obj, new List<CKA> { CKA.CKA_VALUE });
                            shsss = v[0].GetValueAsByteArray();

                            s.Logout();
                            break;
                        }

                        s.Logout();
                    }
                }
            }

            if(shsss == null)
            {
                GenerateKey();
            }
        }

        public override Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        public override Context GenerateKey()
        {
            var pair = generator.GenerateKeyPair();

            pk_oce = (ECPublicKeyParameters)pair.Public;

            sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            shsss = sk_oce.CalculateAgreement(pk_sd).ToByteArrayFixed();

            return this;
        }

        protected override Memory<byte> Key => pk_oce.AsMemory();
        protected override byte Algorithm => 49;

        public readonly ECDomainParameters domain;
        public readonly IAsymmetricCipherKeyPairGenerator generator;
        public readonly ECPublicKeyParameters pk_sd;

        public ECPublicKeyParameters pk_oce;
        private IBasicAgreement sk_oce;
        private byte[] shsss;
    }
}
