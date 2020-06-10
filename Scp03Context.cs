using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    class Scp03Context
    {
        private static KeyParameter Pkcs5Pbkdf2Hmac(string password, string salt = "Yubico", int iterationCount = 10000, int keySize = 256)
        {
            var pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbkdf2.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), Encoding.UTF8.GetBytes(salt), iterationCount);
            return (KeyParameter)pbkdf2.GenerateDerivedMacParameters(keySize);
        }

        public Scp03Context(string password, Session session = null) : this(Pkcs5Pbkdf2Hmac(password), session)
        {
        }

        public Scp03Context(KeyParameter key, Session session = null)
        {
            var bytes = key.GetKey();
            enc_key = new KeyParameter(bytes, 0, 16);
            mac_key = new KeyParameter(bytes, 16, 16);
            if (session != null)
            {
                var info = new byte[9 + bytes.Length];
                info[0] = 7; // INFO_DEFAULT_KEY
                // Delegated capabilities
                for (int i = 0; i < 8; i++)
                    info[i + 1] = 0xff;
                // Pubkey
                bytes.AsSpan().CopyTo(info.AsSpan(9));
                session.SendCmd(HsmCommand.SetInformation, info);
            }
        }

        public Scp03Session CreateSession(Session session, ushort key_id)
        {
            var host_chal = new byte[8];
            rand.NextBytes(host_chal);
            return new Scp03Session(session, key_id, enc_key, mac_key, host_chal);
        }

        private readonly SecureRandom rand = new SecureRandom();
        private readonly KeyParameter enc_key, mac_key;
    }
}
