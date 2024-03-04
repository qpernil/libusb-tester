using System;
using System.IO;
using System.Text;

namespace libusb
{
    public abstract class Context
    {
        public static Span<byte> ListObjects(Session session, ObjectType type)
        {
            var list_req = new ListObjectsReq
            {
                type = type
            };
            return session.SendCmd(list_req);
        }

        public static Span<byte> DeleteObject(Session session, ushort key_id, ObjectType key_type)
        {
            var delete_req = new DeleteObjectReq
            {
                key_id = key_id,
                key_type = key_type
            };
            return session.SendCmd(delete_req);
        }

        public static Span<byte> PutEcP256Key(Session session, ushort key_id, bool delete = true)
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

            var putasym_req = new PutAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignEcdsa | Capability.DecryptEcdh | Capability.Attest | Capability.ExportUnderWrap,
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
            return session.SendCmd(putasym_req);
        }

        public static Span<byte> PutEd25519Key(Session session, ushort key_id, bool delete = true)
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

            var putasym_req = new PutAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignEddsa | Capability.DecryptEcdh | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = Algorithm.ED25519,
                key = new byte[] {
                    0x01, 0x02, 0x03, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    0xff, 0xff, 0xff, 0xff, 0xff, 0x04, 0x05, 0x06,
                }
            };
            return session.SendCmd(putasym_req);
        }

        public static Span<byte> PutRsaKey(Session session, ushort key_id, Algorithm algorithm, ReadOnlyMemory<byte> key, bool delete = true)
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

            var putasym_req = new PutAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignPkcs | Capability.SignPss | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = algorithm,
                key = key
            };
            return session.SendCmd(putasym_req);
        }

        public static Span<byte> GenerateRsaKey(Session session, ushort key_id, bool delete = true)
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

            var genasym_req = new GenerateAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignPkcs | Capability.SignPss | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = Algorithm.RSA_2048,
            };
            return session.SendCmd(genasym_req);
        }

        public static Span<byte> GenerateEcP256Key(Session session, ushort key_id, bool delete = true)
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

            var genasym_req = new GenerateAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignEcdsa | Capability.DecryptEcdh | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = Algorithm.EC_P256,
            };
            return session.SendCmd(genasym_req);
        }

        public static Span<byte> GenerateEd25519Key(Session session, ushort key_id, bool delete = true)
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

            var genasym_req = new GenerateAsymmetricKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.SignEddsa | Capability.Attest | Capability.ExportUnderWrap,
                algorithm = Algorithm.ED25519,
            };
            return session.SendCmd(genasym_req);
        }

        public static Span<byte> SignEcdsa(Session session, ushort key_id)
        {
            var signecdsa_req = new SignEcdsaReq
            {
                key_id = key_id,
                hash = new byte[20]
            };
            return session.SendCmd(signecdsa_req);
        }

        public static Span<byte> SignEddsa(Session session, ushort key_id)
        {
            var signeddsa_req = new SignEddsaReq
            {
                key_id = key_id,
                hash = new byte[20]
            };
            return session.SendCmd(signeddsa_req);
        }

        public static Span<byte> GenerateAesKey(Session session, ushort key_id, bool delete = true)
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

        public static Span<byte> PutAesKey(Session session, ushort key_id, ReadOnlyMemory<byte> key, bool delete = true)
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

        public static Span<byte> PutOpaque(Session session, ushort object_id, ReadOnlyMemory<byte> data, bool delete = true)
        {
            if (delete)
            {
                try
                {
                    DeleteObject(session, object_id, ObjectType.Opaque);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }

            var req = new PutOpaqueReq
            {
                object_id = object_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities = Capability.ExportUnderWrap,
                algorithm = Algorithm.OPAQUE_DATA,
                data = data
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

        public static Span<byte> PutWrapKey(Session session, ushort key_id, ReadOnlyMemory<byte> key, bool delete = true)
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

        public static Span<byte> ExportWrapped(Session session, ushort key_id, ObjectType target_type, ushort target_key, byte format = 0)
        {
            var exportwrapped_req = new ExportWrappedReq
            {
                key_id = key_id,
                target_type = target_type,
                target_key = target_key,
                format = format
            };
            return session.SendCmd(exportwrapped_req);
        }

        public static Span<byte> ImportWrapped(Session session, ushort key_id, ReadOnlyMemory<byte> wrapped_key, ushort delete = 0)
        {
            if (delete > 0)
            {
                try
                {
                    DeleteObject(session, delete, ObjectType.AsymmetricKey);
                }
                catch (IOException e)
                {
                    Console.WriteLine(e.Message);
                }
            }
            var importwrapped_req = new ImportWrappedReq
            {
                key_id = key_id,
                wrapped_key = wrapped_key
            };
            return session.SendCmd(importwrapped_req);
        }

        public static Span<byte> GetPubKey(Session session, ushort key_id, out Algorithm algo) {
            var getpub_req = new GetPubKeyReq
            {
                key_id = key_id
            };
            var ret = session.SendCmd(getpub_req);
            algo = (Algorithm)ret[0];
            return ret.Slice(1);
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
