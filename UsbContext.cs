using System;
using System.Collections.Generic;
using System.IO;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbContext : IDisposable
    {
        public UsbContext()
        {
            libusb = new LibUsb("/Users/PNilsson/Firmware/YubiCrypt/yubi-ifx-common/sim/yubicrypt/build/libusb-1.0.dylib");
            var status = libusb.init(out ctx);
            if (status != 0)
                throw new IOException($"libusb.init failed: {status}");
        }

        public void Dispose()
        {
            libusb.exit(ctx);
        }

        public IEnumerable<IntPtr> GetDeviceList()
        {
            var ret = libusb.get_device_list(ctx, out var device_list);
            if (ret < 0)
                throw new IOException($"libusb.get_device_list failed: {ret}");
            for (int i = 0; i < ret; i++)
            {
                yield return Marshal.ReadIntPtr(device_list, i * IntPtr.Size);
            }
            libusb.free_device_list(device_list, 1);
        }

        public int GetDeviceDescriptor(IntPtr device, out device_descriptor descriptor)
        {
            descriptor = new device_descriptor();
            var status = libusb.get_device_descriptor(device, ref descriptor);
            if (status != 0)
                throw new IOException($"libusb.get_device_descriptor failed: {status}");
            return status;
        }

        public UsbSession CreateSession(IntPtr device)
        {
            return new UsbSession(libusb, device);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr ctx;
    }
}
