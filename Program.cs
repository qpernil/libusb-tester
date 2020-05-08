using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace libusb
{
    struct PutAuthKeyReq
    {
        public ushort key_id; // 0
        public byte[] label; // 2
        public ushort domains; // 42
        public uint capabilities2; // 44
        public uint capabilities; // 48
        public byte algorithm; // 52
        public uint delegated_caps2; // 53
        public uint delegated_caps; // 57
        public byte[] key; // 61

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label);
            s.Write(domains);
            s.Write(capabilities2);
            s.Write(capabilities);
            s.WriteByte(algorithm);
            s.Write(delegated_caps2);
            s.Write(delegated_caps);
            s.Write(key);
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

        static byte[] x9_63_kdf(ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, int length)
        {
            var digest = new Sha256Digest();
            var size = digest.GetDigestSize();
            var offs = 0;
            var cnt = 0U;
            var ms = new MemoryStream();
            ms.Write(shsee);
            ms.Write(shsss);
            ms.Write(cnt);
            var buf = ms.ToArray();
            var cspan = buf.AsSpan(buf.Length - 4);
            var ret = new byte[size * ((length + size - 1) / size)];
            while (offs < length)
            {
                BinaryPrimitives.WriteUInt32BigEndian(cspan, ++cnt);
                digest.Reset();
                digest.BlockUpdate(buf, 0, buf.Length);
                digest.DoFinal(ret, offs);
                offs += size;
            }
            return ret;
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

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6d, q.AsSpan(1), out var pk_sd));
                    Console.WriteLine("PK.SD");
                    foreach (var b in pk_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    var shsss = ecdh.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(pk_sd), domain)).ToByteArrayUnsigned();

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6e, q2.AsSpan(1), out var ret));
                    var shs_sd = ret.Slice(0, 5 * 32);
                    var epk_sd = ret.Slice(5 * 32);

                    Console.WriteLine("ShS.SD");
                    foreach (var b in shs_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    Console.WriteLine("ePK.SD");
                    foreach (var b in epk_sd)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    var shsee = ecdh2.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(epk_sd), domain)).ToByteArrayUnsigned();
                    Console.WriteLine("ShSee");
                    foreach (var b in shsee)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    var shs_oce = x9_63_kdf(shsee, shsss, 5 * 32);
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
