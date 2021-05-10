using System;
using System.Buffers;
using System.IO;
using System.Text;

namespace libusb
{
    public class UsbDevice : IDisposable
    {
        public UsbDevice(LibUsb libusb, UsbDescriptor descriptor, int configuration, byte control_endpoint)
        {
            this.libusb = libusb;
            this.descriptor = descriptor;
            this.configuration = configuration;
            this.control_endpoint = control_endpoint;
            var status = libusb.open(descriptor.device, out device_handle);
            if (status != 0)
            {
                throw new IOException($"libusb.open_device: {libusb.StrError(status)}");
            }
            status = libusb.get_configuration(device_handle, out var current_conf);
            if (status != 0)
            {
                libusb.close(device_handle);
                throw new IOException($"libusb.get_configuration: {libusb.StrError(status)}");
            }
            if (configuration != current_conf)
            {
                status = libusb.set_configuration(device_handle, configuration);
                if (status != 0)
                {
                    libusb.close(device_handle);
                    throw new IOException($"libusb.set_configuration: {libusb.StrError(status)}");
                }
            }
        }

        public void Dispose()
        {
            libusb.close(device_handle);
        }

        public int GetConfiguration()
        {
            var status = libusb.get_configuration(device_handle, out var current_conf);
            if (status != 0)
            {
                throw new IOException($"libusb.get_configuration: {libusb.StrError(status)}");
            }
            return current_conf;
        }

        public string GetStringDescriptor(byte index, ushort langid = 0, int max = 1024)
        {
            if (index == 0)
            {
                throw new IOException($"control_transfer({control_endpoint}): Invalid descriptor index");
            }
            var mem = ArrayPool<byte>.Shared.Rent(max);
            var ret = libusb.control_transfer(device_handle, control_endpoint, 0x06, (ushort)(0x300 | index), langid, mem, (ushort)max, 1000);
            if (ret < 0)
            {
                ArrayPool<byte>.Shared.Return(mem);
                throw new IOException($"control_transfer({control_endpoint}): {libusb.StrError(ret)}");
            }
            var descriptor = Encoding.Unicode.GetString(mem, 2, ret - 2);
            ArrayPool<byte>.Shared.Return(mem);
            return descriptor;
        }

        public string SafeGetStringDescriptor(byte index, ushort langid = 0, int max = 1024)
        {
            if (index == 0)
            {
                return null;
            }
            var mem = ArrayPool<byte>.Shared.Rent(max);
            var ret = libusb.control_transfer(device_handle, control_endpoint, 0x06, (ushort)(0x300 | index), langid, mem, (ushort)max, 1000);
            if (ret < 0)
            {
                ArrayPool<byte>.Shared.Return(mem);
                return null;
            }
            var descriptor = Encoding.Unicode.GetString(mem, 2, ret - 2);
            ArrayPool<byte>.Shared.Return(mem);
            return descriptor;
        }

        public string SerialNumber => SafeGetStringDescriptor(descriptor.descriptor.iSerialNumber);
        public string Manufacturer => SafeGetStringDescriptor(descriptor.descriptor.iManufacturer);
        public string Product => SafeGetStringDescriptor(descriptor.descriptor.iProduct);

        public void Reset()
        {
            var status = libusb.reset_device(device_handle);
            if (status != 0)
            {
                throw new IOException($"libusb.reset_device: {libusb.StrError(status)}");
            }
        }

        public UsbSession Claim(int interface_number, int alt_setting = -1, byte write_endpoint = 0x01, byte read_endpoint = 0x81)
        {
            return new UsbSession(libusb, device_handle, configuration, interface_number, alt_setting, write_endpoint, read_endpoint);
        }

        private readonly LibUsb libusb;
        private readonly UsbDescriptor descriptor;
        private readonly IntPtr device_handle;
        private readonly int configuration;
        private readonly byte control_endpoint;
    }
}
