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
            var ms = new MemoryStream();
            //Label
            for (int i = 0; i < 11; i++)
                ms.WriteByte(0);
            ms.WriteByte(type);
            // Delimiter
            ms.WriteByte(0);
            ms.Write(L);
            // i
            ms.WriteByte(1);
            ms.Write(context);

            var cmac = new CMac(new AesEngine());
            cmac.Init(key);
            cmac.BlockUpdate(ms);
            var result = new byte[cmac.GetMacSize()];
            cmac.DoFinal(result, 0);

            return new KeyParameter(result, 0, L / 8);
        }

        public int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output)
        {
            // TODO: Encrypt / Decrypt if key_enc != null

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

            return session.Transfer(cmd, ms.AsSpan(), out output);
        }

        public Scp03Session(ISession session, ushort key_id, KeyParameter enc_key, KeyParameter mac_key, byte[] host_chal)
        {
            this.session = session;
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            session.Transfer(create_req.Command, create_req.AsSpan(), out var create_resp);
            session_id = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_crypto = create_resp.Slice(1 + 8);

            var context = new byte[host_chal.Length + card_chal.Length];
            host_chal.CopyTo(context.AsSpan(0));
            card_chal.CopyTo(context.AsSpan(host_chal.Length));

            key_mac = Scp03Cryptogram(mac_key, 6, context, 0x80);
            key_rmac = Scp03Cryptogram(mac_key, 7, context, 0x80);
            var card_crypto_host = Scp03Cryptogram(key_mac, 0, context, 0x40).GetKey();
            var host_crypto = Scp03Cryptogram(key_mac, 1, context, 0x40).GetKey();

            if (!card_crypto.SequenceEqual(card_crypto_host))
            {
                throw new IOException($"The card cryptogram was invalid");
            }

            var auth_req = new AuthenticateSessionReq
            {
                session_id = session_id,
                host_crypto = host_crypto
            };
            Transfer(auth_req.Command, auth_req.AsSpan(), out _);

            // Only set this after having authenticated 
            key_enc = Scp03Cryptogram(enc_key, 4, context, 0x80);
        }

        public void Dispose()
        {
        }

        private readonly ISession session;
        private readonly byte session_id;
        private readonly KeyParameter key_mac, key_rmac, key_enc;
        private readonly byte[] mac_chaining = new byte[16];
    }
}
