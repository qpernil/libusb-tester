using System;
using System.Buffers.Binary;
using System.Diagnostics;
using System.IO;

namespace libusb
{
    public interface IWriteable
    {
        HsmCommand Command { get; }
        void WriteTo(Stream s);
    }

    public abstract class Session : IDisposable
    {
        public Span<byte> SendCmd(IWriteable input, int max = 2048 + 3)
        {
            return SendCmd(input.Command, input.AsSpan(), max);
        }
        public Span<byte> SendCmd(HsmCommand cmd, ReadOnlySpan<byte> input = default, int max = 2048 + 3)
        {
            var mem = new byte[max];
            mem[0] = (byte)cmd;
            BinaryPrimitives.WriteUInt16BigEndian(mem.AsSpan(1), (ushort)input.Length);
            input.CopyTo(mem.AsSpan(3));

            var sw = Stopwatch.StartNew();
            Console.WriteLine($"{GetType().Name}.{cmd}...");
            var ret = Transfer(mem, input.Length + 3);
            Console.WriteLine($"{GetType().Name}.{cmd} {sw.Elapsed.TotalMilliseconds}ms.");

            if (ret[0] != ((byte)cmd | 0x80))
            {
                throw new IOException($"The {cmd} command returned {ret.Length} bytes: {(HsmError)ret[3]}");
            }

            var len = BinaryPrimitives.ReadUInt16BigEndian(ret.Slice(1, 2));
            return ret.Slice(3, len);
        }
        public abstract Span<byte> Transfer(byte[] input, int length);
        public abstract void Dispose();
    }
}
