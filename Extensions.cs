﻿using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Math.EC;

namespace libusb
{
    public static class Extensions
    {
        public static Memory<byte> EncodePoint(this ECPoint point)
        {
            return point.GetEncoded().AsMemory(1);
        }

        public static ECPoint DecodePoint(this ECCurve curve, ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return curve.DecodePoint(bytes);
        }

        public static byte[] ToByteArrayFixed(this BigInteger num, int size = 32)
        {
            var ret = num.ToByteArrayUnsigned();
            if(ret.Length < size)
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

        public static void BlockUpdate(this IMac mac, ReadOnlySpan<byte> input)
        {
            var bytes = ArrayPool<byte>.Shared.Rent(input.Length);
            input.CopyTo(bytes);
            mac.BlockUpdate(bytes, 0, input.Length);
            ArrayPool<byte>.Shared.Return(bytes);
        }

        public static void BlockUpdate(this IDigest digest, MemoryStream input)
        {
            digest.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static void BlockUpdate(this IMac mac, MemoryStream input)
        {
            mac.BlockUpdate(input.GetBuffer(), 0, (int)input.Length);
        }

        public static Span<byte> AsSpan(this MemoryStream s)
        {
            return s.GetBuffer().AsSpan(0, (int)s.Length);
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

        public static Span<byte> AsSpan(this IWriteable w)
        {
            var s = new MemoryStream();
            w.WriteTo(s);
            return s.AsSpan();
        }
    }
}
