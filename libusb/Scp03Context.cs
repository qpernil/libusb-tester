using System;
using System.Text;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Scp03Context : Context
    {
        public static KeyParameter Pkcs5Pbkdf2Hmac(string password, string salt = "Yubico", int iterationCount = 10000, int keySize = 256)
        {
            var pbkdf2 = new Pkcs5S2ParametersGenerator(new Sha256Digest());
            pbkdf2.Init(PbeParametersGenerator.Pkcs5PasswordToBytes(password.ToCharArray()), Encoding.UTF8.GetBytes(salt), iterationCount);
            return (KeyParameter)pbkdf2.GenerateDerivedMacParameters(keySize);
        }

        public Scp03Context(string password) : this(Pkcs5Pbkdf2Hmac(password).GetKey())
        {
        }

        public Scp03Context(byte[] bytes)
        {
            enc_key = new KeyParameter(bytes, 0, 16);
            mac_key = new KeyParameter(bytes, 16, 16);
            Key = bytes;
        }

        public Scp03Session CreateSession(Session session, ushort key_id)
        {
            return new Scp03Session(session, key_id, enc_key, mac_key, RandBytes(8));
        }

        public byte[] RandBytes(ushort len)
        {
            var bytes = new byte[len];
            rand.NextBytes(bytes);
            return bytes;
        }

        protected override Memory<byte> Key { get; }
        protected override Algorithm Algo => Algorithm.AES128_YUBICO_AUTHENTICATION;

        private readonly Random rand = Random.Shared;
        private readonly KeyParameter enc_key, mac_key;
    }
}
