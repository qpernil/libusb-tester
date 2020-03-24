using System;
using System.IO;
using Org.BouncyCastle.Asn1.Nist;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;
using Org.BouncyCastle.Security;

namespace libusb
{
    class Program
    {
        static void Main(string[] args)
        {
            var p256 = NistNamedCurves.GetByName("P-256");
            var domain = new ECDomainParameters(p256.Curve, p256.G, p256.N);
            var gen = GeneratorUtilities.GetKeyPairGenerator("ECDH");
            gen.Init(new ECKeyGenerationParameters(domain, new SecureRandom()));
            var pair = gen.GenerateKeyPair();
            var agreement = AgreementUtilities.GetBasicAgreement("ECDH");
            agreement.Init(pair.Private);
            var pub = (ECPublicKeyParameters)pair.Public;
            var q = pub.Q.GetEncoded();

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
                    Console.WriteLine(Convert.ToBase64String(pubkey));

                    Console.WriteLine(libusb.TransferUsb(device_handle, 0x6e, q, out var shared));
                    Console.WriteLine(Convert.ToBase64String(shared));

                    var shared2 = agreement.CalculateAgreement(new ECPublicKeyParameters(domain.Curve.DecodePoint(pubkey.ToArray()), domain)).ToByteArray();
                    Console.WriteLine(Convert.ToBase64String(shared2));

                    Console.WriteLine(libusb.release_interface(device_handle, 0));
                    libusb.close(device_handle);
                }
            }
            libusb.exit(ctx);
        }
    }
}
