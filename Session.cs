using System;
using System.Buffers.Binary;
using System.IO;

namespace libusb
{
    public interface IWriteable
    {
        byte Command { get; }
        void WriteTo(Stream s);
    }

    public abstract class Session : IDisposable
    {
        public Span<byte> SendCmd(IWriteable input)
        {
            return SendCmd(input.Command, input.AsSpan());
        }
        public Span<byte> SendCmd(byte cmd, ReadOnlySpan<byte> input = default, int max = 2048 + 3)
        {
            var mem = new byte[max];
            mem[0] = cmd;
            BinaryPrimitives.WriteUInt16BigEndian(mem.AsSpan(1), (ushort)input.Length);
            input.CopyTo(mem.AsSpan(3));

            var ret = Transfer(mem, input.Length + 3);

            if (ret[0] != (cmd | 0x80))
            {
                throw new IOException($"The {cmd:x} command returned {ret.Length} bytes and error {ret[3]}");
            }

            var len = BinaryPrimitives.ReadUInt16BigEndian(ret.Slice(1));
            return ret.Slice(3, len);
        }
        public abstract Span<byte> Transfer(byte[] input, int length);
        public virtual void Dispose() { }
    }
}
