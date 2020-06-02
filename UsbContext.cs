using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbContext : IDisposable
    {
        public UsbContext()
        {
            libusb = new LibUsb("/Users/PNilsson/Firmware/YubiCrypt/yubi-ifx-common/sim/yubicrypt/build/libusb-1.0.dylib");
            libusb.init(out ctx);
        }

        public void Dispose()
        {
            libusb.exit(ctx);
        }

        public IEnumerable<IntPtr> GetDeviceList()
        {
            var ret = libusb.get_device_list(ctx, out var device_list);
            for (int i = 0; i < ret; i++)
            {
                yield return Marshal.ReadIntPtr(device_list, i * IntPtr.Size);
            }
            libusb.free_device_list(device_list, 1);
        }

        public int GetDeviceDescriptor(IntPtr device, ref device_descriptor descriptor)
        {
            return libusb.get_device_descriptor(device, ref descriptor);
        }

        public UsbSession CreateSession(IntPtr device)
        {
            return new UsbSession(libusb, device);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr ctx;
    }
}
