using System;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbDescriptor
    {
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
            interface_descriptors = new InterfaceDescriptor[config_descriptor.bNumInterfaces];
            for (byte i = 0; i < config_descriptor.bNumInterfaces; i++)
            {
                var intf = Extensions.PtrToStructureAt<libusb_interface>(config_descriptor.Interfaces, i);
                interface_descriptors[i] = new InterfaceDescriptor(intf.altsetting);
            }
            libusb.free_config_descriptor(config_ptr);
        }

        public long Id => device.ToInt64();
        public ushort Vendor => device_descriptor.idVendor;
        public ushort Product => device_descriptor.idProduct;
        public byte NumConfigurations => device_descriptor.bNumConfigurations;
        public byte Configuration => config_descriptor.bConfigurationValue;

        public bool IsYubiHsm => Vendor == 0x1050 && Product == 0x30;
        public bool IsCCID => interface_descriptors.Any(d => d.IsCCID);

        public readonly LibUsb libusb;
        public readonly IntPtr device;
        public readonly device_descriptor device_descriptor;
        public readonly config_descriptor config_descriptor;
        public readonly InterfaceDescriptor[] interface_descriptors;
    }
}
