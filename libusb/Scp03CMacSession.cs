﻿using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03CMacSession : Session
    {
        public override string ToString()
        {
            return $"Scp03CMacSession on {session}";
        }
        public override Span<byte> Transfer(byte[] input, int length)
        {
            // Adjust encoded length to include mac
            BinaryPrimitives.WriteUInt16BigEndian(input.AsSpan(1), (ushort)(length + 5));

            cmac.Init(key_mac);
            cmac.BlockUpdate(mac_chaining);
            cmac.BlockUpdate(input, 0 , length);
            cmac.DoFinal(mac_chaining, 0);

            mac_chaining.AsSpan(0, 8).CopyTo(input.AsSpan(length));

            var output = session.Transfer(input, length + 8);

            if (output.Length >= 8)
            {
                var message = output.Slice(0, output.Length - 8);
                var mac = output.Slice(output.Length - 8);

                var bytes = new byte[16];
                cmac.Init(key_rmac);
                cmac.BlockUpdate(mac_chaining);
                cmac.BlockUpdate(message);
                cmac.DoFinal(bytes, 0);

                var mac_host = bytes.AsSpan(0, 8);

                if (!mac.SequenceEqual(mac_host))
                {
                    throw new IOException("The cmac was invalid");
                }

                // Adjust endcocded length to not include mac 
                BinaryPrimitives.WriteUInt16BigEndian(output.Slice(1), (ushort)(message.Length - 3));

                return output.Slice(0, output.Length - 8);
            }

            return output;
        }

        public Scp03CMacSession(IMac cmac, Session session, KeyParameter key_mac, KeyParameter key_rmac, byte[] mac_chaining)
        {
            this.cmac = cmac;
            this.session = session;
            this.key_mac = key_mac;
            this.key_rmac = key_rmac;
            this.mac_chaining = mac_chaining;
        }

        public override void Dispose()
        {
        }

        private readonly IMac cmac;
        private readonly Session session;
        private readonly KeyParameter key_mac, key_rmac;
        private readonly byte[] mac_chaining;
    }
}
