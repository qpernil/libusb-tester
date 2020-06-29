using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    class Scp03Context : Context
    {
        private static KeyParameter Pkcs5Pbkdf2Hmac(string password, string salt = "Yubico", int iterationCount = 10000, int keySize = 256)
        {
            var pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbkdf2.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), Encoding.UTF8.GetBytes(salt), iterationCount);
            return (KeyParameter)pbkdf2.GenerateDerivedMacParameters(keySize);
        }

        public Scp03Context(string password) : this(Pkcs5Pbkdf2Hmac(password))
        {
        }

        public Scp03Context(KeyParameter key)
        {
            key_bytes = key.GetKey();
            enc_key = new KeyParameter(key_bytes, 0, 16);
            mac_key = new KeyParameter(key_bytes, 16, 16);
        }

        public override Session CreateSession(Session session, ushort key_id)
        {
            var host_chal = new byte[8];
            rand.NextBytes(host_chal);
            return new Scp03Session(session, key_id, enc_key, mac_key, host_chal);
        }

        public override Context GenerateKeyPair()
        {
            return this;
        }

        protected override Memory<byte> Key => key_bytes;
        protected override byte Algorithm => 38;

        private readonly SecureRandom rand = new SecureRandom();
        private readonly KeyParameter enc_key, mac_key;
        private readonly byte[] key_bytes;
    }
}
