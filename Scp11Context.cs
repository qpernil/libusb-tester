using System;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    public class Scp11Context
    {
        public Scp11Context(Session session, ushort key_id = 0)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);

            generator = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            generator.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));

            var pair = generator.GenerateKeyPair();

            var pubkey = (ECPublicKeyParameters)pair.Public;
            pk_oce = pubkey.Q.GetEncoded().AsMemory(1);

            sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            pk_sd = session.SendCmd(HsmCommand.GetScp11PubKey).ToArray();

            shsss = sk_oce.CalculateAgreement(DecodePoint(pk_sd.Span)).ToByteArrayUnsigned();

            // Update the stored auth key since we don't persist the client static key
            if (key_id > 0)
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
                    key = pk_oce
                };
                session.SendCmd(putauth_req);
            }
        }

        public ECPublicKeyParameters DecodePoint(ReadOnlySpan<byte> point)
        {
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(point), domain);
        }

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        internal readonly ECDomainParameters domain;
        internal readonly IAsymmetricCipherKeyPairGenerator generator;
        internal readonly IBasicAgreement sk_oce;
        internal readonly Memory<byte> pk_oce, pk_sd, shsss;
    }
}
