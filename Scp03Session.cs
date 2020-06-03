using System;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03Session : Session
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

        public override int Transfer(byte cmd, ReadOnlySpan<byte> input, out Span<byte> output)
        {
            // TODO: Encrypt / Decrypt using key_enc and ctr
            throw new NotImplementedException();
        }

        public Scp03Session(Session session, ushort key_id, KeyParameter enc_key, KeyParameter mac_key, byte[] host_chal)
        {
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            session.Transfer(create_req, out var create_resp);
            SessionId = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_crypto = create_resp.Slice(1 + 8);

            var context = new byte[host_chal.Length + card_chal.Length];
            host_chal.CopyTo(context.AsSpan(0));
            card_chal.CopyTo(context.AsSpan(host_chal.Length));

            key_enc = Scp03Cryptogram(enc_key, 4, context, 0x80);
            var key_mac = Scp03Cryptogram(mac_key, 6, context, 0x80);
            var key_rmac = Scp03Cryptogram(mac_key, 7, context, 0x80);
            var card_crypto_host = Scp03Cryptogram(key_mac, 0, context, 0x40).GetKey();
            var host_crypto = Scp03Cryptogram(key_mac, 1, context, 0x40).GetKey();

            if (!card_crypto.SequenceEqual(card_crypto_host))
            {
                throw new IOException($"The card cryptogram was invalid");
            }

            this.session = new Scp03CMacSession(session, key_mac, key_rmac);

            var auth_req = new AuthenticateSessionReq
            {
                session_id = SessionId,
                host_crypto = host_crypto
            };
            this.session.Transfer(auth_req, out _);
        }

        public byte SessionId { get; }

        private readonly Session session;
        private readonly KeyParameter key_enc;
        private readonly byte[] ctr = new byte[16];
    }
}
