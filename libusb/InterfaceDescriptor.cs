using System;
using System.Runtime.InteropServices;

namespace libusb
{
    public class InterfaceDescriptor
    {
        public InterfaceDescriptor(nint intf)
        {
            interface_descriptor = Marshal.PtrToStructure<interface_descriptor>(intf);
            UsbDescriptor.parseExtra(interface_descriptor);
            endpoint_descriptors = new endpoint_descriptor[interface_descriptor.bNumEndpoints];
            for (byte i = 0; i < interface_descriptor.bNumEndpoints; i++)
            {
                endpoint_descriptors[i] = Extensions.PtrToStructureAt<endpoint_descriptor>(interface_descriptor.Endpoints, i);
                UsbDescriptor.parseExtra(endpoint_descriptors[i]);
            }
        }

        public bool IsCCID => interface_descriptor.bInterfaceClass == 0x0b;

        public readonly interface_descriptor interface_descriptor;
        public readonly endpoint_descriptor[] endpoint_descriptors;
    }
}
