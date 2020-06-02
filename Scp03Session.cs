using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    class Scp03Session : ISession
    {
        static KeyParameter Scp03Cryptogram(KeyParameter key, byte type, ReadOnlySpan<byte> context, ushort L)
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
            var result = new byte[cmac.GetMacSize()];
            cmac.DoFinal(result, 0);

            return new KeyParameter(result, 0, L / 8);
        }

        public int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output)
        {
            // TODO: Encrypt / Decrypt

            var ms = new MemoryStream();
            ms.Write(mac_chaining);
            ms.WriteByte(cmd);
            ms.Write((ushort)(input.Length + 8));
            ms.Write(input);

            var cmac = new CMac(new AesEngine());
            cmac.Init(key_mac);
            cmac.BlockUpdate(ms.ToArray());
            cmac.DoFinal(mac_chaining, 0);

            ms = new MemoryStream();
            ms.Write(input);
            ms.Write(mac_chaining.AsSpan(0, 8));

            return session.Transfer(cmd, ms.ToArray(), out output);
        }

        public Scp03Session(ISession session, ushort key_id, KeyParameter enc_key, KeyParameter mac_key, byte[] host_chal)
        {
            this.session = session;
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            Console.WriteLine(session.Transfer(0x03, create_req.ToBytes(), out var create_resp));
            session_id = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_gram = create_resp.Slice(1 + 8);

            var context = new byte[host_chal.Length + card_chal.Length];
            host_chal.CopyTo(context.AsSpan(0));
            card_chal.CopyTo(context.AsSpan(host_chal.Length));

            key_enc = Scp03Cryptogram(enc_key, 4, context, 0x80);
            key_mac = Scp03Cryptogram(mac_key, 6, context, 0x80);
            key_rmac = Scp03Cryptogram(mac_key, 7, context, 0x80);
            var card_gram2 = Scp03Cryptogram(key_mac, 0, context, 0x40).GetKey();
            var host_gram = Scp03Cryptogram(key_mac, 1, context, 0x40).GetKey();

            if (!card_gram.SequenceEqual(card_gram2))
            {
                throw new IOException($"The card cryptogram was invalid");
            }

            var auth_req = new AuthenticateSessionReq
            {
                session_id = session_id,
                host_crypto = host_gram,
            };
            Console.WriteLine(Transfer(0x04, auth_req.ToBytes(), out _));

            authenticated = true;
        }

        public void Dispose()
        {
        }

        private readonly ISession session;
        private readonly byte session_id;
        private readonly KeyParameter key_enc, key_mac, key_rmac;
        private readonly byte[] mac_chaining = new byte[16];
        private readonly bool authenticated = false;
    }
}
