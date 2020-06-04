using System;
using System.Buffers;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Math.EC;

namespace libusb
{
    class PutAuthKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public Memory<byte> label; // 2
        public ushort domains; // 42
        public uint capabilities2; // 44
        public uint capabilities; // 48
        public byte algorithm; // 52
        public uint delegated_caps2; // 53
        public uint delegated_caps; // 57
        public Memory<byte> key; // 61

        public byte Command => 0x44;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write(capabilities2);
            s.Write(capabilities);
            s.WriteByte(algorithm);
            s.Write(delegated_caps2);
            s.Write(delegated_caps);
            s.Write(key.Span);
        }
    }

    class DeleteObjectReq : IWriteable
    {
        public ushort key_id;
        public byte key_type;

        public byte Command => 0x58;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte(key_type);
        }
    }

    class CreateSessionReq : IWriteable
    {
        public ushort key_id;
        public Memory<byte> buf;

        public byte Command => 0x03;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(buf.Span);
        }
    }

    class AuthenticateSessionReq : IWriteable
    {
        public byte session_id;
        public Memory<byte> host_crypto;

        public byte Command => 0x04;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(host_crypto.Span);
        }
    }

    class SessionReq : IWriteable
    {
        public byte session_id;
        public Memory<byte> encrypted;

        public byte Command => 0x05;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(encrypted.Span);
        }
    }

    static class Program
    {
        public static ECPoint DecodePoint(this ECCurve curve, ReadOnlySpan<byte> point)
        {
            var bytes = new byte[point.Length + 1];
            bytes[0] = 4;
            point.CopyTo(bytes.AsSpan(1));
            return curve.DecodePoint(bytes);
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

        static void Main(string[] args)
        {
            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    var descriptor = new device_descriptor();
                    usb_ctx.GetDeviceDescriptor(device, ref descriptor);
                    Console.WriteLine($"Vendor 0x{descriptor.idVendor:x} Product 0x{descriptor.idProduct:x}");
                    if (descriptor.idVendor == 0x1050 && descriptor.idProduct == 0x30)
                    {
                        using (var usb_session = usb_ctx.CreateSession(device))
                        {
                            usb_session.GetStringDescriptor(descriptor.iManufacturer, 0, out var manufacturer);
                            usb_session.GetStringDescriptor(descriptor.iProduct, 0, out var product);
                            usb_session.GetStringDescriptor(descriptor.iSerialNumber, 0, out var serial);
                            Console.WriteLine($"Manufacturer '{manufacturer}' Product '{product}' Serial '{serial}'");

                            using (var scp03_session = new Scp03Context("password").CreateSession(usb_session, 1))
                            {
                                using (var scp11_session = new Scp11Context(scp03_session, 2).CreateSession(usb_session, 2))
                                {
                                    var pk_sd1 = usb_session.SendCmd(0x6d);
                                    var pk_sd2 = scp03_session.SendCmd(0x6d);
                                    var pk_sd3 = scp11_session.SendCmd(0x6d);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
