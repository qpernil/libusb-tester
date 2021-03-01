using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        public IEnumerable<UsbDescriptor> GetDeviceList()
        {
            var ret = libusb.get_device_list(ctx, out var device_list);
            if (ret < 0)
                throw new IOException($"libusb.get_device_list: {libusb.StrError(ret)}");
            try
            {
                for (int i = 0; i < ret; i++)
                {
                    yield return new UsbDescriptor(libusb, Marshal.ReadIntPtr(device_list, i * IntPtr.Size));
                }
            }
            finally
            {
                libusb.free_device_list(device_list, 1);
            }
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

        public UsbDevice Open(UsbDescriptor descriptor, int configuration, byte control_endpoint = 0x80)
        {
            return new UsbDevice(libusb, descriptor, configuration, control_endpoint);
        }

        public IEnumerable<UsbDevice> OpenDevices(Func<UsbDescriptor, bool> filter, int configuration, byte control_endpoint = 0x80)
        {
            return GetDeviceList().Where(filter).Select(d => Open(d, configuration, control_endpoint));
        }

        private readonly LibUsb libusb;
        private readonly IntPtr ctx;
    }
}
