using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Paddings;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public abstract class Scp03CryptoSession : Session
    {
        public override Span<byte> Transfer(byte[] input, int length)
        {
            var enc_ctr = new byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(enc_ctr.AsSpan(8), ++ctr);
            engine.Init(true, key_enc);
            engine.ProcessBlock(enc_ctr, 0, enc_ctr, 0);
            var parameters = new ParametersWithIV(key_enc, enc_ctr);
            cipher.Init(true, parameters);
            var unwrap = new SessionReq
            {
                session_id = session_id,
                encrypted = cipher.DoFinal(input, 0, length)
            };
            var output = session.SendCmd(unwrap);

            if (output[0] != session_id)
            {
                throw new IOException($"Invalid session in unwrap response");
            }

            cipher.Init(false, parameters);
            return cipher.DoFinal(output.Slice(1).ToArray());
        }

        public override void Dispose() {
            SendCmd(0x40);
        }

        protected readonly AesEngine engine = new AesEngine();
        protected readonly PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new ISO7816d4Padding());
        protected Session session;
        protected byte session_id;
        protected KeyParameter key_enc;
        private ulong ctr = 0;
    }
}
