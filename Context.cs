using System;
using System.IO;
using System.Text;

namespace libusb
{
    public abstract class Context
    {
        public void PutAuthKey(Session session, ushort key_id)
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
                algorithm = Algorithm,
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                key = Key.AsMemory(1)
            };
            session.SendCmd(putauth_req);
        }

        public void ChangeAuthKey(Session session, ushort key_id)
        {
            var req = new ChangeAuthKeyReq
            {
                key_id = key_id,
                algorithm = Algorithm,
                key = Key.AsMemory(1)
            };
            session.SendCmd(req);
        }

        public void SetDefaultKey(Session session)
        {
            var req = new SetDefaltKeyReq
            {
                delegated_caps2 = 0xffffffff,
                delegated_caps = 0xffffffff,
                buf = Key.AsMemory(1)
            };
            foreach (var b in req.buf.Span)
                Console.Write($"{b:x2}");
            Console.WriteLine();

            session.SendCmd(req);
        }

        protected abstract byte[] Key { get; }
        protected abstract byte Algorithm { get; }
    }
}
