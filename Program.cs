using System;

namespace usblib_tester
{
    class Program
    {
        static void Main(string[] args)
        {
            using (var libusb = new LibUsb("/Users/PNilsson/Firmware/YubiCrypt/yubi-ifx-common/sim/yubicrypt/build/libusb-1.0.dylib"))
            {
                libusb.init(out var ctx);
                foreach (var device in libusb.GetUsbDevices(ctx))
                {
                    var descriptor = new LibUsb.device_descriptor();
                    libusb.get_device_descriptor(device, ref descriptor);
                    Console.WriteLine($"Vendor {descriptor.idVendor:x} Product {descriptor.idProduct:x}");
                    if (descriptor.idVendor == 0x1050 && descriptor.idProduct == 0x30)
                    {
                        //libusb.ref_device(device);
                        //libusb.unref_device(device);
                        Console.WriteLine(libusb.open(device, out var device_handle));
                        Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iManufacturer, out var manufacturer));
                        Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iProduct, out var product));
                        Console.WriteLine(libusb.GetStringDescriptor(device_handle, descriptor.iSerialNumber, out var serial));
                        Console.WriteLine($"Manufacturer {manufacturer} Product {product} Serial {serial}");
                        Console.WriteLine(libusb.claim_interface(device_handle, 0));
                        Console.WriteLine(libusb.TransferUsb(device_handle, 0x6d, ReadOnlySpan<byte>.Empty, out var pubkey));
                        Console.WriteLine(Convert.ToBase64String(pubkey));
                        Console.WriteLine(libusb.release_interface(device_handle, 0));
                        libusb.close(device_handle);
                    }
                }
                libusb.exit(ctx);
            }
        }
    }
}
