using System;
using System.IO;

namespace libusb
{
    public interface IWriteable
    {
        public void WriteTo(Stream s);
    }

    public interface IReadable
    {
        public void ReadFrom(Stream s);
    }

    public interface ISession
    {
        public int Transfer(byte cmd, IWriteable input, IReadable output);
    }
}
