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
    public abstract class Scp03CryptoSession : Session
    {
        public override Span<byte> Transfer(byte[] input, int length)
        {
            var iv = new byte[16];
            BinaryPrimitives.WriteUInt64BigEndian(iv.AsSpan(8), ++ctr);
            ecb_cipher.Init(true, key_enc);
            var parameters = new ParametersWithIV(key_enc, ecb_cipher.DoFinal(iv));
            cipher.Init(true, parameters);

            var session_req = new SessionCommandReq
            {
                session_id = session_id,
                encrypted = cipher.DoFinal(input, 0, length)
            };
            var output = session.SendCmd(session_req);

            if (output[0] != session_id)
            {
                throw new IOException("Invalid session_id in session response");
            }

            cipher.Init(false, parameters);
            return cipher.DoFinal(output.Slice(1).ToArray());
        }

        public override void Dispose()
        {
            SendCmd(HsmCommand.CloseSession);
        }

        public byte[] EcbCrypt(bool forEncryption, byte[] key, byte[] input)
        {
            ecb_cipher.Init(forEncryption, new KeyParameter(key));
            return ecb_cipher.DoFinal(input);
        }

        public byte[] CbcCrypt(bool forEncryption, byte[] key, byte[] iv, byte[] input)
        {
            cbc_cipher.Init(forEncryption, new ParametersWithIV(new KeyParameter(key), iv));
            return cbc_cipher.DoFinal(input);
        }

        public Scp03CryptoSession()
        {
            ecb_cipher = new BufferedBlockCipher(new AesEngine());
            cbc_cipher = new BufferedBlockCipher(new CbcBlockCipher(new AesEngine()));
            cipher = new PaddedBufferedBlockCipher(new CbcBlockCipher(new AesEngine()), new ISO7816d4Padding());
            cmac = new CMac(new AesEngine());
        }

        private readonly BufferedBlockCipher ecb_cipher;
        private readonly BufferedBlockCipher cbc_cipher;
        private readonly PaddedBufferedBlockCipher cipher;
        private ulong ctr;

        protected readonly IMac cmac;
        protected Session session;
        protected byte session_id;
        protected KeyParameter key_enc;
    }
}
