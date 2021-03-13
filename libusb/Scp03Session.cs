using System;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03Session : Scp03CryptoSession
    {
        private KeyParameter ComputeCryptogram(KeyParameter key, byte type, ReadOnlySpan<byte> context, ushort L)
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

            cmac.Init(key);
            cmac.BlockUpdate(ms);
            var result = new byte[cmac.GetMacSize()];
            cmac.DoFinal(result, 0);

            return new KeyParameter(result, 0, L / 8);
        }

        public Scp03Session(Session session, ushort key_id, KeyParameter enc_key, KeyParameter mac_key, ReadOnlyMemory<byte> host_chal)
        {
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            var create_resp = session.SendCmd(create_req);

            session_id = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_crypto = create_resp.Slice(1 + 8, 8);

            var context = new byte[host_chal.Length + card_chal.Length];
            host_chal.CopyTo(context);
            card_chal.CopyTo(context.AsSpan(host_chal.Length));

            key_enc = ComputeCryptogram(enc_key, 4, context, 0x80);
            var key_mac = ComputeCryptogram(mac_key, 6, context, 0x80);
            var key_rmac = ComputeCryptogram(mac_key, 7, context, 0x80);
            var card_crypto_host = ComputeCryptogram(key_mac, 0, context, 0x40).GetKey();
            var host_crypto = ComputeCryptogram(key_mac, 1, context, 0x40).GetKey();

            if (!card_crypto.SequenceEqual(card_crypto_host))
            {
                throw new IOException("The card cryptogram was invalid");
            }

            this.session = new Scp03CMacSession(cmac, session, key_mac, key_rmac, new byte[16]);

            var auth_req = new AuthenticateSessionReq
            {
                session_id = session_id,
                host_crypto = host_crypto
            };
            this.session.SendCmd(auth_req);
        }

        public Scp03Session(Session session, ushort key_id, Session auth_session, ushort auth_key_id)
        {
            var host_chal = auth_session.SendCmd(new GetPseudoRandomReq { length = 8 }).ToArray();
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            var create_resp = session.SendCmd(create_req);

            session_id = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_crypto = create_resp.Slice(1 + 8, 8);

            var client_auth = new ClientAuthReq
            {
                key_id = auth_key_id,
                host_chal = host_chal,
                card_chal = card_chal.ToArray(),
                card_crypto = card_crypto.ToArray()
            };
            var auth_resp = auth_session.SendCmd(client_auth).ToArray();

            key_enc = new KeyParameter(auth_resp, 0, 16);
            var key_mac = new KeyParameter(auth_resp, 16, 16);
            var key_rmac = new KeyParameter(auth_resp, 32, 16);
            var host_crypto = auth_resp.AsMemory(48, 8);

            this.session = new Scp03CMacSession(cmac, session, key_mac, key_rmac, new byte[16]);

            var auth_req = new AuthenticateSessionReq
            {
                session_id = session_id,
                host_crypto = host_crypto
            };
            this.session.SendCmd(auth_req);
        }
    }
}
