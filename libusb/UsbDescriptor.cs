using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbDescriptor
    {
        public static T PtrToStructureAt<T>(IntPtr pointer, int index)
        {
            return Marshal.PtrToStructure<T>(pointer + index * Marshal.SizeOf<T>());
        }

        public UsbDescriptor(LibUsb libusb, IntPtr device)
        {
            this.libusb = libusb;
            this.device = device;
            var status = libusb.get_device_descriptor(device, ref device_descriptor);
            if (status != 0)
            {
                throw new IOException($"libusb.get_device_descriptor: {libusb.StrError(status)}");
            }
            status = libusb.get_active_config_descriptor(device, out var config_ptr);
            if (status != 0)
            {
                throw new IOException($"libusb.get_active_config_descriptor: {libusb.StrError(status)}");
            }
            config_descriptor = Marshal.PtrToStructure<config_descriptor>(config_ptr);
            interface_descriptors = new interface_descriptor[config_descriptor.bNumInterfaces];
            for (byte i = 0; i < config_descriptor.bNumInterfaces; i++)
            {
                var intf = PtrToStructureAt<libusb_interface>(config_descriptor.Interfaces, i);
                interface_descriptors[i] = Marshal.PtrToStructure<interface_descriptor>(intf.altsetting);
            }
            libusb.free_config_descriptor(config_ptr);
        }

        public long Id => device.ToInt64();
        public ushort Vendor => device_descriptor.idVendor;
        public ushort Product => device_descriptor.idProduct;
        public byte Configuration => config_descriptor.bConfigurationValue;

        public bool IsYubiHsm => Vendor == 0x1050 && Product == 0x30;
        public bool IsCCID => interface_descriptors.Any(d => d.bInterfaceClass == 0x0b);

        public readonly LibUsb libusb;
        public readonly IntPtr device;
        public readonly device_descriptor device_descriptor;
        public readonly config_descriptor config_descriptor;
        public readonly interface_descriptor[] interface_descriptors;
    }
}
