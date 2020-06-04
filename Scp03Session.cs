using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03Session : Session
    {
        public static KeyParameter Scp03Cryptogram(KeyParameter key, byte type, ReadOnlySpan<byte> context, ushort L)
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

        private ParametersWithIV IncrementCtr()
        {
            var enc_ctr = new byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(enc_ctr.AsSpan(8), ++ctr);
            engine.ProcessBlock(enc_ctr, 0, enc_ctr, 0);
            return new ParametersWithIV(key_enc, enc_ctr);
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            var enc_ctr = IncrementCtr();
            cipher.Init(true, enc_ctr);
            var unwrap = new UnwrapReq
            {
                session_id = SessionId,
                encrypted = cipher.DoFinal(input, 0, length)
            };
            var output = session.SendCmd(unwrap);

            if (output[0] != SessionId)
            {
                throw new IOException($"Invalid session in unwrap response");
            }

            cipher.Init(false, enc_ctr);
            return cipher.DoFinal(output.Slice(1).ToArray());
        }

        public Scp03Session(Session session, ushort key_id, KeyParameter enc_key, KeyParameter mac_key, byte[] host_chal)
        {
            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = host_chal
            };
            var create_resp = session.SendCmd(create_req);
            SessionId = create_resp[0];
            var card_chal = create_resp.Slice(1, 8);
            var card_crypto = create_resp.Slice(1 + 8, 8);

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
            this.session.SendCmd(auth_req);

            engine.Init(true, key_enc);
        }

        public byte SessionId { get; }

        private readonly Session session;
        private readonly KeyParameter key_enc;
        private readonly AesEngine engine = new AesEngine();
        private readonly IBufferedCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new ISO7816d4Padding());
        private ulong ctr = 0;
    }
}
