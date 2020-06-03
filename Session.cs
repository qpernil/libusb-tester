using System;
using System.IO;

namespace libusb
{
    public interface IWriteable
    {
        byte Command { get; }
        void WriteTo(Stream s);
    }

    public interface IReadable
    {
        void ReadFrom(Stream s);
    }

    public abstract class Session : IDisposable
    {
        public int Transfer(IWriteable input, out Span<byte> output)
        {
            return Transfer(input.Command, input.AsSpan(), out output);
        }
        public abstract int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output);
        public virtual void Dispose() { }
    }
}
