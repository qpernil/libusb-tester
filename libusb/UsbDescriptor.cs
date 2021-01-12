using System;
using System.IO;

namespace libusb
{
    public class UsbDescriptor
    {
        public UsbDescriptor(LibUsb libusb, IntPtr device)
        {
            this.device = device;
            var status = libusb.get_device_descriptor(device, ref descriptor);
            if (status != 0)
            {
                throw new IOException($"libusb.get_device_descriptor: {libusb.StrError(status)}");
            }
        }

        public long Id => device.ToInt64();
        public ushort Vendor => descriptor.idVendor;
        public ushort Product => descriptor.idProduct;

        public bool IsYubiHsm => Vendor == 0x1050 && Product == 0x30;

        public IntPtr device;
        public device_descriptor descriptor;
    }
}
