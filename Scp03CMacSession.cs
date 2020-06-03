using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03CMacSession : Session
    {
        public override int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output)
        {
            var ms = new MemoryStream();
            ms.Write(mac_chaining);
            ms.WriteByte(cmd);
            ms.Write((ushort)(input.Length + 8));
            ms.Write(input);

            var cmac = new CMac(new AesEngine());
            cmac.Init(key_mac);
            cmac.BlockUpdate(ms);
            cmac.DoFinal(mac_chaining, 0);

            ms.SetLength(0);
            ms.Write(input);
            ms.Write(mac_chaining.AsSpan(0, 8));

            var ret = session.Transfer(cmd, ms.AsSpan(), out output);

            if (output.Length > 0)
            {
                // TODO : Verify rmac using key_rmac and mac_chaining
                throw new NotImplementedException();
            }

            return ret;
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
    }
}
