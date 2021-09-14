using System;
using System.IO;
using System.Linq;
using System.Text;

namespace libusb
{
    public abstract class Context
    {
        public Span<byte> DeleteObject(Session session, ushort key_id, byte key_type)
        {
            var delete_req = new DeleteObjectReq
            {
                key_id = key_id,
                key_type = key_type
            };
            return session.SendCmd(delete_req);
        }

        public Span<byte> PutEcdhKey(Session session, ushort key_id, bool delete = true)
        {
            if (delete)
            {
                try
                {
                    DeleteObject(session, key_id, 3);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            // ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632550
            // ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff

            var putecdh_req = new PutAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.DecryptEcdh | Capability.Attest,
                algorithm = 12,
                key = new byte[] {
//                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
//                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                    0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50-8
                }
            };
            return session.SendCmd(putecdh_req);
        }

        public Span<byte> PutAuthKey(Session session, ushort key_id, bool delete = true)
        {
            if(delete)
            {
                try
                {
                    DeleteObject(session, key_id, 2);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var putauth_req = new PutAuthKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.GetRandom | Capability.DeleteAuthKey | Capability.WriteAuthKey | Capability.ChangeAuthKey | Capability.Attest,
                algorithm = Algorithm,
                delegated_caps = Capability.GetRandom | Capability.DeleteAuthKey | Capability.WriteAuthKey | Capability.ChangeAuthKey | Capability.Attest,
                key = Key
            };
            return session.SendCmd(putauth_req);
        }

        public void ChangeAuthKey(Session session, ushort key_id)
        {
            var req = new ChangeAuthKeyReq
            {
                key_id = key_id,
                algorithm = Algorithm,
                key = Key
            };
            session.SendCmd(req);
        }

        public void SetDefaultKey(Session session)
        {
            var req = new SetDefaltKeyReq
            {
                delegated_caps = (Capability)0xffffffffffffffff,
                key = Key
            };
            foreach (var b in req.key.Span)
                Console.Write($"{b:x2}");
            Console.WriteLine();

            session.SendCmd(req);
        }

        protected abstract Memory<byte> Key { get; }
        protected abstract byte Algorithm { get; }
    }
}
