using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;

namespace libusb
{
    public class UsbSession : ISession
    {
        public UsbSession(LibUsb libusb, IntPtr device)
        {
            this.libusb = libusb;
            libusb.open(device, out device_handle);
            libusb.claim_interface(device_handle, 0);
        }

        public void Dispose()
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

        public int WriteUsb(byte[] data)
        {
            var ret = libusb.bulk_transfer(device_handle, 1, data, data.Length, out var transferred, 0);
            if (ret < 0)
            {
                return ret;
            }
            if (transferred % 64 == 0)
            {
                ret = libusb.bulk_transfer(device_handle, 1, data, 0, out _, 0);
                if (ret < 0)
                {
                    return ret;
                }
            }
            return transferred;
        }

        public int ReadUsb(out Span<byte> data, int max = 2048 + 3)
        {
            var mem = new byte[max];
            var ret = libusb.bulk_transfer(device_handle, 0x81, mem, max, out var transferred, 0);
            if (ret < 0)
            {
                data = Span<byte>.Empty;
                return ret;
            }
            data = mem.AsSpan(0, transferred);
            return transferred;
        }

        public int TransferUsb(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output, int max = 2048 + 3)
        {
            var mem = new byte[max];
            mem[0] = cmd;
            BinaryPrimitives.WriteUInt16BigEndian(mem.AsSpan(1, 2), (ushort)input.Length);
            input.CopyTo(mem.AsSpan(3, max - 3));

            var ret = libusb.bulk_transfer(device_handle, 1, mem, 3 + input.Length, out var transferred, 0);
            if (ret < 0)
            {
                output = Span<byte>.Empty;
                return ret;
            }

            if (transferred % 64 == 0)
            {
                ret = libusb.bulk_transfer(device_handle, 1, mem, 0, out _, 0);
                if (ret < 0)
                {
                    output = Span<byte>.Empty;
                    return ret;
                }
            }

            ret = libusb.bulk_transfer(device_handle, 0x81, mem, max, out transferred, 0);
            if (ret < 0)
            {
                output = Span<byte>.Empty;
                return ret;
            }

            if(transferred < 3 || mem[0] != (cmd | 0x80))
            {
                throw new IOException($"The {cmd:x} command returned {transferred} bytes and error {mem[3]}");
            }

            var len = BinaryPrimitives.ReadUInt16BigEndian(mem.AsSpan(1, 2));
            output = mem.AsSpan(0, transferred).Slice(3, len);
            return len;
        }

        public int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output)
        {
            return TransferUsb(cmd, input, out output);
        }

        private readonly LibUsb libusb;
        private readonly IntPtr device_handle;
    }
}
