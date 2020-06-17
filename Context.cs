using System;
using System.IO;
using System.Text;

namespace libusb
{
    public abstract class Context
    {
        public Context PutAuthKey(Session session, ushort key_id)
        {
            try
            {
                var delete_req = new DeleteObjectReq
                {
                    key_id = key_id,
                    key_type = 2
                };
                session.SendCmd(delete_req);

            }
            catch (IOException e)
            {
                Console.WriteLine(e.Message);
            }

            var putauth_req = new PutAuthKeyReq
            {
                key_id = key_id,
                label = Encoding.UTF8.GetBytes("0123456789012345678901234567890123456789"),
                domains = 0xffff,
                capabilities2 = 0xffffffff,
                capabilities = 0xffffffff,
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                key = AuthKey
            };
            putauth_req.algorithm = (byte)(putauth_req.key.Length == 64 ? 49 : 38);
            session.SendCmd(putauth_req);
            return this;
        }

        public Context SetDefaultKey(Session session)
        {
            var req = new SetDefaltKeyReq
            {
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                buf = AuthKey
            };
            session.SendCmd(req);
            return this;
        }

        public abstract Session CreateSession(Session session, ushort key_id);

        protected abstract Memory<byte> AuthKey { get; }
    }
}
