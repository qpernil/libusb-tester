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

            pk_oce = (ECPublicKeyParameters)pair.Public;

            sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            pk_sd = DecodePoint(session.SendCmd(HsmCommand.GetScp11PubKey));

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
                    key = pk_oce.AsMemory()
                };
                session.SendCmd(putauth_req);
            }
            else
            {
                var req = new SetDefaltKeyReq
                {
                    delegated_caps2 = 0xffffffff,
                    delegated_caps = 0xffffffff,
                    buf = pk_oce.AsMemory()
                };
                session.SendCmd(req);
            }
        }

        public ECPublicKeyParameters DecodePoint(ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(bytes), domain);
        }

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        internal readonly ECDomainParameters domain;
        internal readonly IAsymmetricCipherKeyPairGenerator generator;
        internal readonly IBasicAgreement sk_oce;
        internal readonly ECPublicKeyParameters pk_oce, pk_sd;
    }
}
