using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    class Scp03Session : ISession
    {
        static Span<byte> Scp03Cryptogram(KeyParameter key, byte type, ReadOnlySpan<byte> context, ushort L = 0x80)
        {
            var s = new MemoryStream();
            //Label
            for (int i = 0; i < 11; i++)
                s.WriteByte(0);
            s.WriteByte(type);
            // Delimiter
            s.WriteByte(0);
            s.Write(L);
            // i
            s.WriteByte(1);
            s.Write(context);

            var cmac = new CMac(new AesEngine());
            cmac.Init(key);
            cmac.BlockUpdate(s.ToArray());
            var result = new byte[16];
            cmac.DoFinal(result, 0);

            return result.AsSpan(0, L / 8);
        }

        public int Transfer(byte cmd, IWriteable input, IReadable output)
        {
            throw new NotImplementedException();
        }

        public Scp03Session(KeyParameter enc_key, KeyParameter mac_key, byte[] host_chal, ushort key_id)
        {
            var ms = new MemoryStream();
            new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            }.WriteTo(ms);
        }

        public readonly KeyParameter key_enc, key_mac, key_rmac;
    }
}
