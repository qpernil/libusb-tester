using System;
using System.Buffers;
using System.IO;
using System.Text;

namespace libusb
{
    public class UsbDevice : IDisposable
    {
        public UsbDevice(LibUsb libusb, IntPtr device, int configuration)
        {
            this.libusb = libusb;
            var status = libusb.open(device, out device_handle);
            if (status != 0)
            {
                throw new IOException($"libusb.open_device: {libusb.StrError(status)}");
            }
            if(configuration >= 0)
            {
                status = libusb.set_configuration(device_handle, configuration);
                if (status != 0)
                {
                    throw new IOException($"libusb.open_device: {libusb.StrError(status)}");
                }
            }
        }

        public int GetConfiguration()
        {
            var status = libusb.get_configuration(device_handle, out var configuration);
            if (status != 0)
            {
                throw new IOException($"libusb.get_configuration: {libusb.StrError(status)}");
            }
            return configuration;
        }

        public string GetStringDescriptor(byte index, ushort langid = 0, int max = 1024)
        {
            var mem = ArrayPool<byte>.Shared.Rent(max);
            var ret = libusb.control_transfer(device_handle, 0x80, 0x06, (ushort)(0x300 | index), langid, mem, (ushort)max, 1000);
            if (ret < 0)
            {
                ArrayPool<byte>.Shared.Return(mem);
                throw new IOException($"control_transfer(out): {libusb.StrError(ret)}");
            }
            var descriptor = Encoding.Unicode.GetString(mem, 2, ret - 2);
            ArrayPool<byte>.Shared.Return(mem);
            return descriptor;
        }

        public void Reset()
        {
            var status = libusb.reset_device(device_handle);
            if (status != 0)
            {
                throw new IOException($"libusb.reset_device: {libusb.StrError(status)}");
            }
        }

        public UsbSession Claim(int interface_number = 0, byte write_endpoint = 0x01, byte read_endpoint = 0x81, int alt_setting = -1)
        {
            return new UsbSession(libusb, device_handle, interface_number, write_endpoint, read_endpoint, alt_setting);
        }

        public void Dispose()
        {
            libusb.close(device_handle);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr device_handle;
    }
}
