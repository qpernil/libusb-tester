using System;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace libusb
{
    static class Program
    {
        static ECPoint DecodePoint(this ECCurve curve, ReadOnlySpan<byte> point)
        {
            var bytes = new byte[65];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return curve.DecodePoint(bytes);
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

            var libusb = new LibUsb("/Users/PNilsson/Firmware/YubiCrypt/yubi-ifx-common/sim/yubicrypt/build/libusb-1.0.dylib");
            Console.WriteLine(libusb.init(out var ctx));
            foreach (var device in libusb.GetUsbDevices(ctx))
            {
                var descriptor = new device_descriptor();
                Console.WriteLine(libusb.get_device_descriptor(device, ref descriptor));
                Console.WriteLine($"Vendor {descriptor.idVendor:x} Product {descriptor.idProduct:x}");
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
                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6d, Span<byte>.Empty, out var pubkey));

                    var shared = ecdh.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(pubkey), domain)).ToByteArrayUnsigned();
                    foreach (var b in shared)
                        Console.Write($"{b:x2}");
                    Console.WriteLine();

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6e, q.AsSpan(1), out var shared2));
                    foreach (var b in shared2)
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
