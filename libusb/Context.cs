using System;
using System.IO;
using System.Linq;
using System.Text;

namespace libusb
{
    public abstract class Context
    {
        public Span<byte> DeleteObject(Session session, ushort key_id, ObjectType key_type)
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
                    DeleteObject(session, key_id, ObjectType.AsymmetricKey);
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
                capabilities = Capability.DecryptEcdh | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = Algorithm.EC_P256,
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

        public Span<byte> GenerateAesKey(Session session, ushort key_id, bool delete = true)
        {
            if (delete)
            {
                try
                {
                    DeleteObject(session, key_id, ObjectType.SymmetricKey);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var req = new GenerateSymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.DecryptEcb | Capability.EncryptEcb | Capability.DecryptCbc | Capability.EncryptCbc | Capability.ExportUnderWrap,
                algorithm = Algorithm.AES_128
            };
            return session.SendCmd(req);
        }

        public Span<byte> PutAesKey(Session session, ushort key_id, ReadOnlyMemory<byte> key, bool delete = true)
        {
            if (delete)
            {
                try
                {
                    DeleteObject(session, key_id, ObjectType.SymmetricKey);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var req = new PutSymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.DecryptEcb | Capability.EncryptEcb | Capability.DecryptCbc | Capability.EncryptCbc | Capability.ExportUnderWrap,
                algorithm = Algorithm.AES_128,
                key = key
            };
            return session.SendCmd(req);
        }

        public Span<byte> PutAuthKey(Session session, ushort key_id, bool delete = true)
        {
            if(delete)
            {
                try
                {
                    DeleteObject(session, key_id, ObjectType.AuthenticationKey);
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
                capabilities = (Capability)0xffffffffffffffff,
                algorithm = Algo,
                delegated_caps = (Capability)0xffffffffffffffff,
                key = Key
            };
            return session.SendCmd(putauth_req);
        }

        public void ChangeAuthKey(Session session, ushort key_id)
        {
            var req = new ChangeAuthKeyReq
            {
                key_id = key_id,
                algorithm = Algo,
                key = Key
            };
            session.SendCmd(req);
        }

        public Span<byte> PutWrapKey(Session session, ushort key_id, ReadOnlyMemory<byte> key, bool delete = true)
        {
            if (delete)
            {
                try
                {
                    DeleteObject(session, key_id, ObjectType.WrapKey);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var putwrap_req = new PutWrapKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = (Capability)0xffffffffffffffff,
                algorithm = Algorithm.AES256_CCM_WRAP,
                delegated_caps = (Capability)0xffffffffffffffff,
                key = key
            };
            return session.SendCmd(putwrap_req);
        }

        public Span<byte> ExportWrapped(Session session, ushort key_id, ObjectType target_type, ushort target_key)
        {
            var exportwrapped_req = new ExportWrappedReq
            {
                key_id = key_id,
                target_type = target_type,
                target_key = target_key
            };
            return session.SendCmd(exportwrapped_req);
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
        protected abstract Algorithm Algo { get; }
    }
}
