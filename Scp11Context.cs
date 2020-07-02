using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Asn1.Nist;
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
            //ms.Write("Yubico");
            var buf = ms.AsSpan();
            var cspan = buf.Slice(shsee.Length + shsss.Length);
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
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(point.ToArray()), domain);
        }

        public Scp11Context(Session session)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);

            generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));


            var bytes = session.SendCmd(HsmCommand.GetDevicePubKey);
            if(bytes[0] != 49)
                throw new IOException($"Unknown device pubkey algorithm: {bytes[0]}");
            bytes[0] = 0x04;
            pk_sd = DecodePoint(bytes);
        }

        public void GenerateKeyPair()
        {
            var pair = generator.GenerateKeyPair();

            pk_oce = (ECPublicKeyParameters)pair.Public;

            sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            shsss = sk_oce.CalculateAgreement(pk_sd).ToByteArrayFixed();
        }

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        protected override byte[] Key => pk_oce.Q.GetEncoded();
        protected override byte Algorithm => 49;

        public readonly ECDomainParameters domain;
        public readonly IAsymmetricCipherKeyPairGenerator generator;
        public readonly ECPublicKeyParameters pk_sd;

        public ECPublicKeyParameters pk_oce;
        protected IBasicAgreement sk_oce;
        protected byte[] shsss;
    }
}
