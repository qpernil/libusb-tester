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

    public interface ISession : IDisposable
    {
        int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output);
    }
}
