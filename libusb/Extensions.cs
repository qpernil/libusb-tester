using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;

namespace libusb
{
    public static class Extensions
    {
        public static byte[] ToByteArrayFixed(this BigInteger num, int size = 32)
        {
            var ret = num.ToByteArrayUnsigned();
            if(ret.Length != size)
            {
                var bytes = new byte[size];
                ret.CopyTo(bytes, size - ret.Length);
                return bytes;
            }
            return ret;
        }

        public static void BlockUpdate(this IDigest digest, ReadOnlySpan<byte> input)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(input.Length);
            input.CopyTo(bytes);
            digest.BlockUpdate(bytes, 0, input.Length);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IDigest digest, ushort value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(2);
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            digest.BlockUpdate(bytes, 0, 2);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IDigest digest, uint value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(4);
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            digest.BlockUpdate(bytes, 0, 4);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IDigest digest, MemoryStream input)
        {
            digest.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static void BlockUpdate(this IDigest digest, string value)
        {
            digest.BlockUpdate(Encoding.UTF8.GetBytes(value));
        }

        public static void BlockUpdate(this IMac mac, ReadOnlySpan<byte> input)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(input.Length);
            input.CopyTo(bytes);
            mac.BlockUpdate(bytes, 0, input.Length);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IMac mac, ushort value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(2);
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            mac.BlockUpdate(bytes, 0, 2);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IMac mac, uint value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(4);
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            mac.BlockUpdate(bytes, 0, 4);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IMac mac, MemoryStream input)
        {
            mac.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static void BlockUpdate(this IMac mac, string value)
        {
            mac.BlockUpdate(Encoding.UTF8.GetBytes(value));
        }

        public static Span<byte> AsSpan(this MemoryStream s)
        {
            return s.GetBuffer().AsSpan(0, (int)s.Length);
        }

        public static Span<byte> AsSpan(this IWriteable w)
        {
            var s = new MemoryStream();
            w.WriteTo(s);
            return s.AsSpan();
        }

        public static void Write(this Stream s, ushort value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(2);
            BinaryPrimitives.WriteUInt16BigEndian(bytes, value);
            s.Write(bytes, 0, 2);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void Write(this Stream s, uint value)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(4);
            BinaryPrimitives.WriteUInt32BigEndian(bytes, value);
            s.Write(bytes, 0, 4);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void Write(this Stream s, string value)
        {
            s.Write(Encoding.UTF8.GetBytes(value));
        }
    }
}
