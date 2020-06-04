using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03CMacSession : Session
    {
        public override Span<byte> Transfer(byte[] input, int length)
        {
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(1), (ushort)(length + 5));

            var ms = new MemoryStream();
            ms.Write(mac_chaining);
            ms.Write(input, 0, length);

            cmac.Init(key_mac);
            cmac.BlockUpdate(ms);
            cmac.DoFinal(mac_chaining, 0);

            mac_chaining.AsSpan(0, 8).CopyTo(input.AsSpan(length));

            var output = session.Transfer(input, length + 8);

            if (output.Length >= 8)
            {
                var message = output.Slice(0, output.Length - 8);
                var mac = output.Slice(output.Length - 8);

                ms.SetLength(0);
                ms.Write(mac_chaining);
                ms.Write(message);

                var bytes = new byte[16];
                cmac.Init(key_rmac);
                cmac.BlockUpdate(ms);
                cmac.DoFinal(bytes, 0);

                var mac_host = bytes.AsSpan(0, 8);

                if (!mac.SequenceEqual(mac_host))
                {
                    throw new IOException($"The cmac was invalid");
                }

                BinaryPrimitives.WriteUInt16BigEndian(output.Slice(1), (ushort)(message.Length - 3));

                return output.Slice(0, output.Length - 8);
            }

            return output;
        }

        public Scp03CMacSession(Session session, KeyParameter key_mac, KeyParameter key_rmac)
        {
            this.session = session;
            this.key_mac = key_mac;
            this.key_rmac = key_rmac;
        }

        private readonly Session session;
        private readonly KeyParameter key_mac, key_rmac;
        private readonly byte[] mac_chaining = new byte[16];
        private readonly IMac cmac = new CMac(new AesEngine());
    }
}
