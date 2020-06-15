using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.IO;
using System.Text;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    public class Scp11Context
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

        public Span<byte> CalculateShs(IBasicAgreement esk_oce, ECPublicKeyParameters epk_sd, int length)
        {
            var shsee = esk_oce.CalculateAgreement(epk_sd).ToByteArrayFixed();

            return X963Kdf(digest, shsee, shsss, length);
        }

        public ECPublicKeyParameters DecodePoint(ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(bytes), domain);
        }

        public void PutAuthKey(Session session, ushort key_id)
        {
            try
            {
                var delete_req = new DeleteObjectReq
                {
                    key_id = key_id,
                    key_type = 2
                };
                session.SendCmd(delete_req);

            }
            catch (IOException e)
            {
                Console.WriteLine(e.Message);
            }

            var putauth_req = new PutAuthKeyReq
            {
                key_id = key_id,
                algorithm = 49,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities2 = 0xffffffff,
                capabilities = 0xffffffff,
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                key = pk_oce.AsMemory()
            };
            session.SendCmd(putauth_req);
        }

        public void SetDefaultKey(Session session)
        {
            var req = new SetDefaltKeyReq
            {
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                buf = pk_oce.AsMemory()
            };
            session.SendCmd(req);
        }

        public Scp11Context(Session session)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);

            generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));

            pk_sd = DecodePoint(session.SendCmd(HsmCommand.GetScp11PubKey));

            var factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, "/usr/local/lib/libykcs11.dylib", AppType.SingleThreaded))
            {
                foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                {
                    using (var s = slot.OpenSession(SessionType.ReadWrite))
                    {
                        s.Login(CKU.CKU_USER, "123456");

                        var keys = s.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 256) });

                        if (keys.Count > 0)
                        {
                            pk_oce = DecodePoint(s.GetAttributeValue(keys[0], new List<CKA> { CKA.CKA_EC_POINT })[0].GetValueAsByteArray().AsSpan(3));

                            var mech = factories.MechanismFactory.Create(CKM.CKM_ECDH1_DERIVE,
                                factories.MechanismParamsFactory.CreateCkEcdh1DeriveParams((ulong)CKD.CKD_NULL, null, pk_sd.Q.GetEncoded()));

                            var obj = s.DeriveKey(mech, keys[0], new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true) });

                            var v = s.GetAttributeValue(obj, new List<CKA> { CKA.CKA_VALUE });
                            shsss = v[0].GetValueAsByteArray();

                            break;
                        }

                        s.Logout();
                    }
                }
            }

            if(shsss == null)
            {
                var pair = generator.GenerateKeyPair();

                pk_oce = (ECPublicKeyParameters)pair.Public;

                sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
                sk_oce.Init(pair.Private);

                shsss = sk_oce.CalculateAgreement(pk_sd).ToByteArrayFixed();
            }

            SetDefaultKey(session);
        }

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        public readonly ECDomainParameters domain;
        public readonly IAsymmetricCipherKeyPairGenerator generator;
        public readonly ECPublicKeyParameters pk_oce, pk_sd;

        private readonly IDigest digest = new Sha256Digest();
        private readonly IBasicAgreement sk_oce;
        private readonly byte[] shsss;
    }
}
