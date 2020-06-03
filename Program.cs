using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace libusb
{
    class PutAuthKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public Memory<byte> label; // 2
        public ushort domains; // 42
        public uint capabilities2; // 44
        public uint capabilities; // 48
        public byte algorithm; // 52
        public uint delegated_caps2; // 53
        public uint delegated_caps; // 57
        public Memory<byte> key; // 61

        public byte Command => 0x44;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write(capabilities2);
            s.Write(capabilities);
            s.WriteByte(algorithm);
            s.Write(delegated_caps2);
            s.Write(delegated_caps);
            s.Write(key.Span);
        }
    }

    class CreateSessionReq : IWriteable
    {
        public ushort key_id;
        public Memory<byte> buf;

        public byte Command => 0x03;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(buf.Span);
        }
    }

    class AuthenticateSessionReq : IWriteable
    {
        public byte session_id;
        public Memory<byte> host_crypto;

        public byte Command => 0x04;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(host_crypto.Span);
        }
    }

    static class Program
    {
        public static ECPoint DecodePoint(this ECCurve curve, ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return curve.DecodePoint(bytes);
        }

        public static void BlockUpdate(this IDigest digest, ReadOnlySpan<byte> input)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(input.Length);
            input.CopyTo(bytes);
            digest.BlockUpdate(bytes, 0, input.Length);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IMac mac, ReadOnlySpan<byte> input)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(input.Length);
            input.CopyTo(bytes);
            mac.BlockUpdate(bytes, 0, input.Length);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IDigest digest, MemoryStream input)
        {
            digest.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static void BlockUpdate(this IMac mac, MemoryStream input)
        {
            mac.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static Span<byte> AsSpan(this MemoryStream s)
        {
            return s.GetBuffer().AsSpan(0, (int)s.Length);
        }

        public static void Write(this Stream s, ushort value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(2);
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            s.Write(bytes, 0, 2);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void Write(this Stream s, uint value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(4);
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            s.Write(bytes, 0, 4);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static Span<byte> AsSpan(this IWriteable w)
        {
            var s = new MemoryStream();
            w.WriteTo(s);
            return s.AsSpan();
        }

        static Span<byte> X963Kdf(IDigest digest, ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, int length)
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
            for (var offs = 0;  offs < length; offs += size)
            {
                BinaryPrimitives.WriteUInt32BigEndian(cspan, ++cnt);
                digest.Reset();
                digest.BlockUpdate(buf);
                digest.DoFinal(ret, offs);
            }
            return ret.AsSpan(0, length);
        }

        static void Main(string[] args)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            var domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);
            var gen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));

            var pair = gen.GenerateKeyPair();
            var pub = (ECPublicKeyParameters)pair.Public;
            var pk_oce = pub.Q.GetEncoded().AsMemory(1);
            var sk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            sk_oce.Init(pair.Private);

            pair = gen.GenerateKeyPair();
            pub = (ECPublicKeyParameters)pair.Public;
            var epk_oce = pub.Q.GetEncoded().AsMemory(1);
            var esk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            esk_oce.Init(pair.Private);

            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    var descriptor = new device_descriptor();
                    Console.WriteLine(usb_ctx.GetDeviceDescriptor(device, ref descriptor));
                    Console.WriteLine($"Vendor 0x{descriptor.idVendor:x} Product 0x{descriptor.idProduct:x}");
                    if (descriptor.idVendor == 0x1050 && descriptor.idProduct == 0x30)
                    {
                        using (var usb_session = usb_ctx.CreateSession(device))
                        {
                            Console.WriteLine(usb_session.GetStringDescriptor(descriptor.iManufacturer, 0, out var manufacturer));
                            Console.WriteLine(usb_session.GetStringDescriptor(descriptor.iProduct, 0, out var product));
                            Console.WriteLine(usb_session.GetStringDescriptor(descriptor.iSerialNumber, 0, out var serial));
                            Console.WriteLine($"Manufacturer '{manufacturer}' Product '{product}' Serial '{serial}'");

                            using (var session = new Scp03Context("password").CreateSession(usb_session, 1))
                            {
                                Console.WriteLine(usb_session.Transfer(0x6d, ReadOnlySpan<byte>.Empty, out var pk_sd));

                                Console.WriteLine("PK.SD");
                                foreach (var b in pk_sd)
                                    Console.Write($"{b:x2}");
                                Console.WriteLine();

                                var putauth_req = new PutAuthKeyReq
                                {
                                    key_id = 2,
                                    algorithm = 49,
                                    label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                                    domains = 0xffff,
                                    capabilities2 = 0xffffffff,
                                    capabilities = 0xffffffff,
                                    delegated_caps2 = 0xffffffff,
                                    delegated_caps = 0xffffffff,
                                    key = pk_oce
                                };

                                Console.WriteLine(usb_session.Transfer(0x6e, putauth_req.AsSpan(), out var putauth_resp));

                                var create_req = new CreateSessionReq
                                {
                                    key_id = 2,
                                    buf = epk_oce
                                };

                                Console.WriteLine(usb_session.Transfer(create_req, out var create_resp));

                                var sess = create_resp[0];
                                var epk_sd = create_resp.Slice(1, 64);
                                var receipt = create_resp.Slice(1 + 64);

                                Console.WriteLine("Session " + sess);

                                Console.WriteLine("ePK.SD");
                                foreach (var b in epk_sd)
                                    Console.Write($"{b:x2}");
                                Console.WriteLine();

                                Console.WriteLine("Receipt.SD");
                                foreach (var b in receipt)
                                    Console.Write($"{b:x2}");
                                Console.WriteLine();

                                var shsss = sk_oce.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(pk_sd), domain)).ToByteArrayUnsigned();
                                var shsee = esk_oce.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(epk_sd), domain)).ToByteArrayUnsigned();

                                var shs_oce = X963Kdf(new Sha256Digest(), shsee, shsss, 4 * 16).ToArray();
                                var receipt_key = new KeyParameter(shs_oce, 0, 16);
                                var enc_key = new KeyParameter(shs_oce, 16, 16);
                                var mac_key = new KeyParameter(shs_oce, 32, 16);
                                var rmac_key = new KeyParameter(shs_oce, 48, 16);

                                var cmac = new CMac(new AesEngine());
                                cmac.Init(receipt_key);
                                cmac.BlockUpdate(epk_sd);
                                cmac.BlockUpdate(epk_oce.Span);
                                var receipt_oce = new byte[16];
                                cmac.DoFinal(receipt_oce, 0);

                                Console.WriteLine("Receipt.OCE");
                                foreach (var b in receipt_oce)
                                    Console.Write($"{b:x2}");
                            }
                        }
                        Console.WriteLine();
                    }
                }
            }
        }
    }
}
