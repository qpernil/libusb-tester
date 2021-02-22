using System;
using System.Collections;
using System.IO;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;

namespace libusb
{
    public class Scp11Context : Context
    {
        public static Span<byte> X963Kdf(IDigest digest, ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, ReadOnlySpan<byte> shared, int length)
        {
            var size = digest.GetDigestSize();
            var cnt = 0U;
            var ret = new byte[size * ((length + size - 1) / size)];
            for (var offs = 0; offs < length; offs += size)
            {
                digest.Reset();
                digest.BlockUpdate(shsee);
                digest.BlockUpdate(shsss);
                digest.BlockUpdate(++cnt);
                digest.BlockUpdate(shared);
                digest.DoFinal(ret, offs);
            }
            return ret.AsSpan(0, length);
        }

        public Span<byte> CalculateShs(ReadOnlySpan<byte> shsee, int length)
        {
            return X963Kdf(new Sha256Digest(), shsee, shsss, new byte[] { 0x3c, 0x88, 0x10 }, length);
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

            Console.WriteLine("PK.SD");
            foreach (var b in bytes)
                Console.Write($"{b:x2}");
            Console.WriteLine();
        }

        public ECPrivateKeyParameters GenerateKeyPair(long priv = 0)
        {
            AsymmetricCipherKeyPair pair;
            if(priv == 0)
            {
                pair = generator.GenerateKeyPair();
            }
            else
            {
                var sk = new ECPrivateKeyParameters(BigInteger.ValueOf(priv), domain);
                var pk = new ECPublicKeyParameters(domain.G.Multiply(sk.D), domain);
                pair = new AsymmetricCipherKeyPair(pk, sk);
            }

            pk_oce = (ECPublicKeyParameters)pair.Public;

            sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            shsss = sk_oce.CalculateAgreement(pk_sd).ToByteArrayFixed();

            return (ECPrivateKeyParameters)pair.Private;
        }

        public X509Certificate GenerateCertificate(AsymmetricKeyParameter signer)
        {
            IDictionary attrs = new Hashtable();
            attrs[X509Name.E] = "per.nilsson@yubico.com";
            attrs[X509Name.CN] = "Per Nilsson";
            attrs[X509Name.O] = "Yubico AB";
            attrs[X509Name.C] = "SE";

            IList ord = new ArrayList();
            ord.Add(X509Name.E);
            ord.Add(X509Name.CN);
            ord.Add(X509Name.O);
            ord.Add(X509Name.C);

            var certGen = new X509V3CertificateGenerator();

            certGen.SetSerialNumber(BigInteger.One);
            certGen.SetIssuerDN(new X509Name(ord, attrs));
            certGen.SetNotBefore(DateTime.Today.Subtract(new TimeSpan(1, 0, 0, 0)));
            certGen.SetNotAfter(DateTime.Today.AddDays(365));
            certGen.SetSubjectDN(new X509Name(ord, attrs));
            certGen.SetPublicKey(pk_oce);
            certGen.AddExtension(X509Extensions.BasicConstraints, true, new BasicConstraints(true));
            certGen.AddExtension(X509Extensions.AuthorityKeyIdentifier, false, new AuthorityKeyIdentifier(SubjectPublicKeyInfoFactory.CreateSubjectPublicKeyInfo(signer)));

            return certGen.Generate(new Asn1SignatureFactory("SHA256withECDSA", signer));
        }

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        protected override Memory<byte> Key => pk_oce.Q.GetEncoded().AsMemory(1);
        protected override byte Algorithm => 49;

        public readonly ECDomainParameters domain;
        public readonly IAsymmetricCipherKeyPairGenerator generator;
        public readonly ECPublicKeyParameters pk_sd;

        public ECPublicKeyParameters pk_oce;
        protected IBasicAgreement sk_oce;
        protected byte[] shsss;
    }
}
