using System;
using System.IO;
using System.Runtime.InteropServices;

namespace libusb
{
    public class UsbSession : Session
    {
        public UsbSession(LibUsb libusb, IntPtr device_handle)
        {
            this.libusb = libusb;
            this.device_handle = device_handle;
            var status = libusb.claim_interface(device_handle, 0);
            if (status != 0)
            {
                throw new IOException($"libusb.claim_interface failed: {libusb.StrError(status)}");
            }
        }

        public override void Dispose()
        {
            libusb.release_interface(device_handle, 0);
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            var ret = libusb.bulk_transfer(device_handle, 0x01, input, length, out var transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer(out) failed with error {libusb.StrError(ret)}");
            }

            if (transferred % 64 == 0)
            {
                ret = libusb.bulk_transfer(device_handle, 0x01, input, 0, out _, 0);
                if (ret < 0)
                {
                    throw new IOException($"bulk_transfer(zero-length packet) failed with error {libusb.StrError(ret)}");
                }
            }

            ret = libusb.bulk_transfer(device_handle, 0x81, input, input.Length, out transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer(in) failed with error {libusb.StrError(ret)}");
            }

            return input.AsSpan(0, transferred);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr device_handle;
    }
}
