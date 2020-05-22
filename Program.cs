using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace libusb
{
    struct PutAuthKeyReq
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

    struct CreateSessionReq
    {
        public ushort key_id;
        public Memory<byte> key;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(key.Span);
        }
    }

    static class Program
    {
        public static ECPoint DecodePoint(this ECCurve curve, ReadOnlySpan<byte> point)
        {
            var bytes = new byte[65];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return curve.DecodePoint(bytes);
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

        static Span<byte> X963Kdf(IDigest digest, ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, int length)
        {
            var size = digest.GetDigestSize();
            var cnt = 0U;
            var ms = new MemoryStream();
            ms.Write(shsee);
            ms.Write(shsss);
            ms.Write(cnt);
            var buf = ms.ToArray();
            var cspan = buf.AsSpan(buf.Length - 4);
            var ret = new byte[size * ((length + size - 1) / size)];
            for (var offs = 0;  offs < length; offs += size)
            {
                BinaryPrimitives.WriteUInt32BigEndian(cspan, ++cnt);
                digest.Reset();
                digest.BlockUpdate(buf, 0, buf.Length);
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
            var q = pub.Q.GetEncoded();
            var ecdh = AgreementUtilities.GetBasicAgreement("ECDH");
            ecdh.Init(pair.Private);

            var pair2 = gen.GenerateKeyPair();
            var pub2 = (ECPublicKeyParameters)pair2.Public;
            var q2 = pub2.Q.GetEncoded();
            var ecdh2 = AgreementUtilities.GetBasicAgreement("ECDH");
            ecdh2.Init(pair2.Private);

            var libusb = new LibUsb("/Users/PNilsson/Firmware/YubiCrypt/yubi-ifx-common/sim/yubicrypt/build/libusb-1.0.dylib");
            Console.WriteLine(libusb.init(out var ctx));
            foreach (var device in libusb.GetUsbDevices(ctx))
            {
                var descriptor = new device_descriptor();
                Console.WriteLine(libusb.get_device_descriptor(device, ref descriptor));
                Console.WriteLine($"Vendor 0x{descriptor.idVendor:x} Product 0x{descriptor.idProduct:x}");
                if (descriptor.idVendor == 0x1050 && descriptor.idProduct == 0x30)
                {
                    //libusb.ref_device(device);
                    //libusb.unref_device(device);
                    Console.WriteLine(libusb.open(device, out var device_handle));
                    Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iManufacturer, 0, out var manufacturer));
                    Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iProduct, 0, out var product));
                    Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iSerialNumber, 0, out var serial));
                    Console.WriteLine($"Manufacturer '{manufacturer}' Product '{product}' Serial '{serial}'");
                    Console.WriteLine(libusb.claim_interface(device_handle, 0));

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6d, Span<byte>.Empty, out var pk_sd));

                    Console.WriteLine("PK.SD");
                    foreach (var b in pk_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    var ms = new MemoryStream();
                    new PutAuthKeyReq
                    {
                        key_id = 2,
                        algorithm = 48,
                        label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                        domains = 0xffff,
                        capabilities2 = 0xffffffff,
                        capabilities = 0xffffffff,
                        delegated_caps2 = 0xffffffff,
                        delegated_caps = 0xffffffff,
                        key = q.AsMemory(1)
                    }.WriteTo(ms);
                    
                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6e, ms.ToArray(), out var ret));

                    ms = new MemoryStream();
                    new CreateSessionReq
                    {
                        key_id = 2,
                        key = q2.AsMemory(1)
                    }.WriteTo(ms);

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x03, ms.ToArray(), out ret));
                    var shs_sd = ret.Slice(1, 5 * 32);
                    var epk_sd = ret.Slice(1 + 5 * 32);

                    Console.WriteLine("ShS.SD");
                    foreach (var b in shs_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    Console.WriteLine("ePK.SD");
                    foreach (var b in epk_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    var shsss = ecdh.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(pk_sd), domain)).ToByteArrayUnsigned();
                    var shsee = ecdh2.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(epk_sd), domain)).ToByteArrayUnsigned();

                    var shs_oce = X963Kdf(new Sha256Digest(), shsee, shsss, 5 * 32);
                    Console.WriteLine("Shs.OCE");
                    foreach (var b in shs_oce)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    Console.WriteLine(libusb.release_interface(device_handle, 0));
                    libusb.close(device_handle);
                }
            }
            libusb.exit(ctx);
        }
    }
}
