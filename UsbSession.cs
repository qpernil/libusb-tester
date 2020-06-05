using System;
using System.Buffers;
using System.IO;
using System.Text;

namespace libusb
{
    public class UsbSession : Session
    {
        public UsbSession(LibUsb libusb, IntPtr device)
        {
            this.libusb = libusb;
            libusb.open(device, out device_handle);
            libusb.claim_interface(device_handle, 0);
        }

        public override void Dispose()
        {
            libusb.release_interface(device_handle, 0);
            libusb.close(device_handle);
        }

        public int GetStringDescriptor(byte index, ushort langid, out string descriptor, int max = 1024)
        {
            var mem = ArrayPool<byte>.Shared.Rent(max);
            var ret = libusb.control_transfer(device_handle, 0x80, 0x06, (ushort)(0x300 | index), langid, mem, (ushort)max, 1000);
            if (ret < 0)
            {
                descriptor = string.Empty;
                ArrayPool<byte>.Shared.Return(mem);
                return ret;
            }
            descriptor = Encoding.Unicode.GetString(mem, 2, ret - 2);
            ArrayPool<byte>.Shared.Return(mem);
            return ret;
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            var ret = libusb.bulk_transfer(device_handle, 0x01, input, length, out var transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer(out) failed with error {ret}");
            }

            if (transferred % 64 == 0)
            {
                ret = libusb.bulk_transfer(device_handle, 0x01, input, 0, out _, 0);
                if (ret < 0)
                {
                    throw new IOException($"bulk_transfer(zero-length packet) failed with error {ret}");
                }
            }

            ret = libusb.bulk_transfer(device_handle, 0x81, input, input.Length, out transferred, 0);
            if (ret < 0)
            {
                throw new IOException($"bulk_transfer(in) failed with error {ret}");
            }

            return input.AsSpan(0, transferred);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr device_handle;
    }
}
