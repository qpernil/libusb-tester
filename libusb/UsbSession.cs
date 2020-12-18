using System;
using System.IO;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbSession : Session
    {
        public UsbSession(LibUsb libusb, IntPtr device_handle, int interface_number, byte write_endpoint, byte read_endpoint, int alt_setting)
        {
            this.libusb = libusb;
            this.device_handle = device_handle;
            this.interface_number = interface_number;
            this.write_endpoint = write_endpoint;
            this.read_endpoint = read_endpoint;
            var status = libusb.claim_interface(device_handle, interface_number);
            if (status != 0)
            {
                throw new IOException($"libusb.claim_interface({interface_number}): {libusb.StrError(status)}");
            }
            if(alt_setting >= 0)
            {
                status = libusb.set_interface_alt_setting(device_handle, interface_number, alt_setting);
                if (status != 0)
                {
                    throw new IOException($"libusb.set_interface_alt_setting({interface_number}, {alt_setting}): {libusb.StrError(status)}");
                }
            }
        }

        public override void Dispose()
        {
            libusb.release_interface(device_handle, interface_number);
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            var ret = libusb.bulk_transfer(device_handle, write_endpoint, input, length, out var transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer({write_endpoint}): {libusb.StrError(ret)}");
            }

            if (transferred % 64 == 0)
            {
                ret = libusb.bulk_transfer(device_handle, write_endpoint, input, 0, out _, 0);
                if (ret < 0)
                {
                    throw new IOException($"bulk_transfer({write_endpoint}) zero-length packet: {libusb.StrError(ret)}");
                }
            }

            ret = libusb.bulk_transfer(device_handle, read_endpoint, input, input.Length, out transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer({read_endpoint}): {libusb.StrError(ret)}");
            }

            return input.AsSpan(0, transferred);
        }

        public void ClearWrite()
        {
            var ret = libusb.clear_halt(device_handle, write_endpoint);
            if (ret < 0)
            {
                throw new IOException($"clear_halt({write_endpoint}): {libusb.StrError(ret)}");
            }
        }

        public void ClearRead()
        {
            var ret = libusb.clear_halt(device_handle, read_endpoint);
            if (ret < 0)
            {
                throw new IOException($"clear_halt({read_endpoint}): {libusb.StrError(ret)}");
            }
        }

        private readonly LibUsb libusb;
        private readonly IntPtr device_handle;
        private readonly int interface_number;
        private readonly byte write_endpoint, read_endpoint;
    }
}
