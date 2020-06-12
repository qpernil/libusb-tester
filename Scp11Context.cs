using System;
using System.Buffers.Binary;
using System.IO;
using System.Text;
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
            var shsss = sk_oce.CalculateAgreement(pk_sd).ToByteArrayFixed();
            var shsee = esk_oce.CalculateAgreement(epk_sd).ToByteArrayFixed();

            return X963Kdf(new Sha256Digest(), shsee, shsss, length);
        }

        public ECPublicKeyParameters DecodePoint(ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return new ECPublicKeyParameters(domain.Curve.DecodePoint(bytes), domain);
        }

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

        public Scp11Session CreateSession(Session session, ushort key_id)
        {
            return new Scp11Session(this, session, key_id);
        }

        public readonly ECDomainParameters domain;
        public readonly IAsymmetricCipherKeyPairGenerator generator;
        public readonly ECPublicKeyParameters pk_oce, pk_sd;

        private readonly IBasicAgreement sk_oce;
    }
}
