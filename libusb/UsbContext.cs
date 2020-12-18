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
            libusb = new LibUsb();
            var status = libusb.init(out ctx);
            if (status != 0)
                throw new IOException($"libusb.init: {libusb.StrError(status)}");
        }

        public void Dispose()
        {
            libusb.exit(ctx);
        }

        public IEnumerable<IntPtr> GetDeviceList()
        {
            var ret = libusb.get_device_list(ctx, out var device_list);
            if (ret < 0)
                throw new IOException($"libusb.get_device_list: {libusb.StrError(ret)}");
            for (int i = 0; i < ret; i++)
            {
                yield return Marshal.ReadIntPtr(device_list, i * IntPtr.Size);
            }
            libusb.free_device_list(device_list, 1);
        }

        public device_descriptor GetDeviceDescriptor(IntPtr device)
        {
            var descriptor = new device_descriptor();
            var status = libusb.get_device_descriptor(device, ref descriptor);
            if (status != 0)
                throw new IOException($"libusb.get_device_descriptor: {libusb.StrError(status)}");
            return descriptor;
        }

        public config_descriptor GetConfigDescriptor(IntPtr device, byte index)
        {
            var status = libusb.get_config_descriptor(device, index, out var descriptor);
            if (status != 0)
                throw new IOException($"libusb.get_config_descriptor({index}): {libusb.StrError(status)}");
            var ret = Marshal.PtrToStructure<config_descriptor>(descriptor);
            libusb.free_config_descriptor(descriptor);
            return ret;
        }

        public UsbDevice Open(IntPtr device, int configuration = -1)
        {
            return new UsbDevice(libusb, device, configuration);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr ctx;
    }
}
