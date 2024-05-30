using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Threading;
using libusb;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb_tester
{
    public class HsmPool
    {
        public void Add(Session session)
        {
            sessions.Add(session);
        }
        public void Init()
        {
            semaphore = new Semaphore(sessions.Count, sessions.Count);
        }
        public SessionHolder GetSession()
        {
            semaphore.WaitOne();
            mutex.WaitOne();
            var ret = new SessionHolder(this, sessions[0]);
            sessions.RemoveAt(0);
            mutex.ReleaseMutex();
            return ret;
        }
        internal void ReleaseSession(Session session)
        {
            mutex.WaitOne();
            sessions.Add(session);
            mutex.ReleaseMutex();
            semaphore.Release();
        }
        private readonly List<Session> sessions = new List<Session>();
        private readonly Mutex mutex = new Mutex();
        private Semaphore semaphore;
    }
    public class SessionHolder : IDisposable
    {
        public SessionHolder(HsmPool owner, Session session)
        {
            this.owner = owner;
            this.session = session;
        }
        public void Dispose()
        {
            owner.ReleaseSession(session);
        }
        private readonly HsmPool owner;
        public readonly Session session;
    }
    public class Key
    {
        public Key(ushort id, Session session)
        {
            this.id = id;
            Add(session);
        }
        public void Add(Session session)
        {
            sessions.Add(session);
        }
        public override string ToString()
        {
            return string.Join(", ", sessions);
        }
        private readonly List<Session> sessions = new List<Session>();
        public readonly ushort id;
    }
    static class Program
    {
        static void Main(string[] args)
        {
            try
            {
                Run(args);
            }
            catch(Exception e)
            {
                Console.WriteLine(e);
            }
        }
        static void ThreadStart(object obj)
        {
            HsmPool pool = (HsmPool)obj;
            for(int i = 0; i < 100; i++)
            {
                using (var holder = pool.GetSession())
                {
                    Console.WriteLine($"Thread {Thread.CurrentThread.ManagedThreadId} using {holder.session}");
                    var pub = Context.SignEddsa(holder.session, 7);
                }
            }
        }
        static void Run1(string[] args)
        {
            using (var usb_ctx = new UsbContext())
            {
                var scp03_context = new Scp03Context("password");
                var devices = usb_ctx.OpenDevices(d => d.IsYubiHsm, 1).ToList();
                var sessions = devices.Select(d => d.Claim(0)).ToList();
                var scp03_sessions = sessions.Select(s => scp03_context.CreateSession(s, 1)).ToList();
                var wrap_key = scp03_context.RandBytes(32);
                scp03_sessions.ForEach(s => Context.PutWrapKey(s, 2, Algorithm.AES256_CCM_WRAP, wrap_key));
                for (ushort i = 3; i < 10; i++)
                {
                    Context.GenerateEd25519Key(scp03_sessions.First(), i);
                    var wrapped_key = Context.ExportWrapped(scp03_sessions.First(), 2, ObjectType.AsymmetricKey, i).ToArray();
                    scp03_sessions.ForEach(s => Context.ImportWrapped(s, 2, wrapped_key, ObjectType.AsymmetricKey, i));
                }
                /*
                Context.DeleteObject(scp03_sessions[0], 3, ObjectType.AsymmetricKey);
                Context.DeleteObject(scp03_sessions[1], 4, ObjectType.AsymmetricKey);
                Context.DeleteObject(scp03_sessions[2], 5, ObjectType.AsymmetricKey);
                Context.DeleteObject(scp03_sessions[3], 6, ObjectType.AsymmetricKey);
                */
                var dict = new Dictionary<string, Key>();
                var pool = new HsmPool();
                foreach(var session in scp03_sessions)
                {
                    var resp = Context.ListObjects(session, ObjectType.AsymmetricKey);
                    while (resp.Length >= 4)
                    {
                        var id = BinaryPrimitives.ReadUInt16BigEndian(resp.Slice(0, 2));
                        var type = resp[2];
                        var seq = resp[3];
                        var pub = BitConverter.ToString(Context.GetPubKey(session, id, out var algo).ToArray()).Replace("-", string.Empty);
                        Console.WriteLine(new { id, type, seq, algo, pub });
                        if(dict.TryGetValue(pub, out var key))
                        {
                            key.Add(session);
                        }
                        else
                        {
                            dict.Add(pub, new Key(id, session));
                        }
                        resp = resp.Slice(4);
                    }
                    pool.Add(session);
                }
                pool.Init();
                List<Thread> threads = new List<Thread>();
                for(int i = 0; i < 100; i++)
                {
                    threads.Add(new Thread(ThreadStart));
                }
                var start = DateTime.Now;
                foreach (var t in threads) t.Start(pool);
                foreach (var t in threads) t.Join();
                var elapsed = DateTime.Now - start;
                Console.WriteLine($"Peformed 10000 operations in {elapsed}");
                scp03_sessions.ForEach(s => s.Dispose());
                sessions.ForEach(s => s.Dispose());
                devices.ForEach(s => s.Dispose());
            }
        }
        static Algorithm AlgoFromBitLength(int bitlength)
        {
            switch(bitlength)
            {
                case 2048: return Algorithm.RSA_2048;
                case 3072: return Algorithm.RSA_3072;
                case 4096: return Algorithm.RSA_4096;
                default: throw new IOException($"Invalid RSA bitlength {bitlength}");
            }
        }
        static void Run(string[] args)
        {
            //var z = new NSRecord("DFFFFFFFFFFFFFFFFF7F8188818180bb5c424c1b3121cf630cbcbaf60fa91e53786d1ab9e8b6e5855acb9afbec944555481d88fcd8e32947f7696d80a8f4df55be51dcb967fc5ef3d213a971a11fee54917cbe10d4b6ba69a71ee1434ce6b6cadb46ceff0bbf2ba832cb5516af35a1debf182e0a57544a64bfe2d0f711cf94dffb44dda9d1d4a9abdf1460e783b6f18203010001");
            /*
            var x = new PCSC("/Users/PNilsson/Firmware/YkPlus/yubi-ifx-common/sim/ykplus/build/libykplus-pcsc.dylib");
            var prc = x.establish_context(PCSC.SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out var pctx);
            var buf = new byte[512];
            int cb = 512;
            prc = x.list_readers(pctx, null, buf, ref cb);
            var s = Encoding.UTF8.GetString(buf, 0, cb);
            Console.WriteLine(s);
            prc = x.release_context(pctx);
            */
            var scp03_context = new Scp03Context("password");
            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    Console.WriteLine($"Id {device.Id} Vendor 0x{device.Vendor:x} Product 0x{device.Product:x}");
                    if (device.IsYubiHsm)
                    {
                        //var config = usb_ctx.GetConfigDescriptor(device, 0);
                        //var config_id = config.bConfigurationValue;
                        using (var usb_device = usb_ctx.Open(device, 1))
                        {
                            Console.WriteLine($"Manufacturer '{usb_device.Manufacturer}' Product '{usb_device.Product}' Serial '{usb_device.SerialNumber}'");
                            using (var usb_session = usb_device.Claim(0))
                            {
                                //usb_session.SendCmd(new SetSerialReq { serial = 12345 });
                                //usb_session.SendCmd(new SetBslCodeReq { code = new byte[16] });
                                //usb_session.SendCmd(new SetBslCodeReq { code = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } });
                                //usb_session.SendCmd(HsmCommand.Bsl);
                                //usb_session.SendCmd(new BslReq { code = new byte[16] });
                                //usb_session.SendCmd(new BslReq { code = new byte[] { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 } });
                                //usb_session.SendCmd(new SetFipsDeviceReq { fips = 1 });
                                //usb_session.SendCmd(new SetDemoModeReq { demo = 0xffff });
                                //usb_session.SendCmd(new SetFuseReq());
                                var resp = usb_session.SendCmd(HsmCommand.Echo, new byte[] { 1, 2, 3, 4, 5 });

                                using (var scp03_session = scp03_context.CreateSession(usb_session, 1))
                                {
                                    //scp03_session.SendCmd(HsmCommand.Reset);
                                    /*
                                    var opts = scp03_session.SendCmd(new GetAlgorithmToggleReq { });
                                    for(int i = 0; i < opts.Length; i += 2)
                                    {
                                        Console.WriteLine($"{opts[i]}:{opts[i + 1]:x2}");
                                        opts[i + 1] = opts[i] == (byte)Algorithm.AES128_YUBICO_AUTHENTICATION ? (byte)0 : (byte)1;
                                    }
                                    Console.WriteLine();
                                    var scp11_context = new Pkcs11Scp11Context(scp03_session);
                                    var res = scp03_session.SendCmd(new PutAlgorithmToggleReq { data = opts.ToArray() });
                                    scp11_context.PutAuthKey(scp03_session, 0);
                                    scp03_context.PutAuthKey(scp03_session, 0);
                                    
                                    res = scp03_session.SendCmd(new PutFipsModeReq { fips = 1 });
                                    var fips = scp03_session.SendCmd(new GetFipsModeReq { });
                                    Console.WriteLine("GetFipsMode over scp03_session");
                                    foreach (var b in fips)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    */
                                    Context.PutOpaque(scp03_session, 3, Algorithm.OPAQUE_DATA, new byte[254]);
                                    var opaque = scp03_session.SendCmd(new GetOpaqueReq { object_id = 3 });

                                    Debug.Assert(opaque.SequenceEqual(new byte[254]));

                                    Context.PutAesKey(scp03_session, 4, new byte[16]);
                                    var encrypted = scp03_session.SendCmd(new EncryptEcbReq { key_id = 4, data = new byte[16*125] });
                                    var decrypted = scp03_session.EcbCrypt(false, new byte[16], encrypted.ToArray());
                                    var decrypted2 = scp03_session.SendCmd(new DecryptEcbReq { key_id = 4, data = encrypted.ToArray() });

                                    Debug.Assert(decrypted.SequenceEqual(decrypted2.ToArray()));

                                    /*
                                    var encrypted2 = scp03_session.SendCmd(new WrapKwpReq { key_id = 4, data = new byte[1125] });
                                    var decrypted3 = scp03_session.SendCmd(new UnwrapKwpReq { key_id = 4, data = encrypted2.ToArray() });

                                    File.WriteAllBytes("kwp-wrapped", encrypted2.ToArray());
                                    File.WriteAllBytes("kwp-unwrapped", decrypted3.ToArray());

                                    Console.Write($"/opt/homebrew/opt/openssl@3/bin/openssl enc -d -id-aes128-wrap-pad -iv A65959A6 -K ");
                                    foreach (var b in new byte[16])
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine(" -in kwp-wrapped");

                                    Console.WriteLine($"KWP wrapped data {encrypted2.Length}");
                                    foreach (var b in encrypted2.ToArray())
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    Console.WriteLine($"KWP unwrapped data {decrypted3.Length}");
                                    foreach (var b in decrypted3.ToArray())
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    */

                                    opaque = scp03_session.SendCmd(new GetOpaqueReq { object_id = 0 });
                                    Console.WriteLine("Opaque data");
                                    foreach (var b in opaque.ToArray())
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    
                                    encrypted = scp03_session.SendCmd(new EncryptCbcReq { key_id = 4, iv = new byte[16], data = new byte[16 * 125] });
                                    decrypted = scp03_session.CbcCrypt(false, new byte[16], new byte[16], encrypted.ToArray());
                                    decrypted2 = scp03_session.SendCmd(new DecryptCbcReq { key_id = 4, iv = new byte[16], data = encrypted.ToArray() });

                                    Debug.Assert(decrypted.SequenceEqual(decrypted2.ToArray()));

                                    var id = Context.PutEcP256Key(scp03_session, 5);
                                    Context.SignEcdsa(scp03_session, 5);
                                    var id2 = Context.PutEd25519Key(scp03_session, 6);
                                    Context.SignEddsa(scp03_session, 6);
                                    var pub = BitConverter.ToString(Context.GetPubKey(scp03_session, 6, out var algo).ToArray()).Replace("-", string.Empty);
                                    Console.WriteLine($"{algo} GetPubKey over scp03_session");
                                    foreach (var b in pub)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var id3 = Context.GenerateEcP256Key(scp03_session, 7);
                                    Context.SignEcdsa(scp03_session, 7);
                                    var id4 = Context.GenerateEd25519Key(scp03_session, 8);
                                    Context.SignEddsa(scp03_session, 8);
                                    Context.PutWrapKey(scp03_session, 2, Algorithm.AES256_CCM_WRAP, new byte[32]);
                                    Context.ExportWrapped(scp03_session, 2, ObjectType.AsymmetricKey, 5);
                                    var ed_key = Context.ExportWrapped(scp03_session, 2, ObjectType.AsymmetricKey, 6).ToArray();
                                    Context.ExportWrapped(scp03_session, 2, ObjectType.AsymmetricKey, 7);
                                    Context.ExportWrapped(scp03_session, 2, ObjectType.AsymmetricKey, 8);
                                    Context.ImportWrapped(scp03_session, 2, ed_key, ObjectType.AsymmetricKey, 6);
                                    pub = BitConverter.ToString(Context.GetPubKey(scp03_session, 6, out algo).ToArray()).Replace("-", string.Empty);
                                    Console.WriteLine($"{algo} After ImportWrapped over scp03_session");
                                    foreach (var b in pub)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    Context.ExportWrapped(scp03_session, 2, ObjectType.SymmetricKey, 4);
                                    Context.ExportWrapped(scp03_session, 2, ObjectType.WrapKey, 2);
                                    var info = scp03_session.SendCmd(HsmCommand.GetDeviceInfo);
                                    Console.WriteLine("DeviceInfo over scp03_session");
                                    foreach (var b in info)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var rand1 = scp03_session.SendCmd(new GetPseudoRandomReq { length = 64 });
                                    Console.WriteLine("GetPseudoRandom over scp03_session");
                                    foreach (var b in rand1)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var context = new Scp11Context(usb_session);
                                    context.PutAuthKey(scp03_session, 3); // Device pubkey in 3
                                    var sk_oce = context.GenerateKeyPair();
                                    //usb_session.SendCmd(new SetAttestKeyReq { algorithm = Algorithm.EC_P256, key = sk_oce.D.ToByteArrayFixed() });
                                    //usb_session.SendCmd(new SetAttestCertReq { cert = Scp11Context.GenerateCertificate(context.pk_oce, sk_oce).GetEncoded() });
                                    var pair = Scp11Context.GenerateRsaKeyPair(2048);
                                    var rsa = (RsaKeyParameters)pair.Public;
                                    var crt = (RsaPrivateCrtKeyParameters)pair.Private;
                                    var p = crt.P.ToByteArrayUnsigned();
                                    var q = crt.Q.ToByteArrayUnsigned();
                                    var n = crt.Modulus.ToByteArrayUnsigned();
                                    Context.PutRsaKey(scp03_session, 4, AlgoFromBitLength(crt.Modulus.BitLength), p.Concat(q).ToArray());
                                    var attestation = scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 0, attest_id = 0 }).ToArray();
                                    File.WriteAllBytes("attestation0.cer", attestation);
                                    Context.PutOpaque(scp03_session, 4, Algorithm.OPAQUE_X509_CERT, attestation);
                                    attestation = scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 4, attest_id = 4 }).ToArray();
                                    File.WriteAllBytes("attestation4.cer", attestation);
                                    Context.SignPkcs1(scp03_session, 4);
                                    Context.SignPss(scp03_session, 4, Algorithm.MGF1_SHA256, new byte[32]);
                                    Console.WriteLine($"<<<<< p {p.Length} q {q.Length} n {n.Length}");
                                    Context.PutWrapKey(scp03_session, 555, AlgoFromBitLength(crt.Modulus.BitLength), p.Concat(q).ToArray());
                                    Context.PutPublicWrapKey(scp03_session, 555, AlgoFromBitLength(rsa.Modulus.BitLength), n);
                                    var wrapped = Context.ExportWrapped(scp03_session, 2, ObjectType.PublicWrapKey, 555).ToArray();
                                    Context.ImportWrapped(scp03_session, 2, wrapped, ObjectType.PublicWrapKey, 555);
                                    wrapped = Context.ExportRsaWrapped(scp03_session, 555, ObjectType.PublicWrapKey, 555, Algorithm.AES_256, Algorithm.RSA_OAEP_SHA256, Algorithm.MGF1_SHA256, new byte[32]).ToArray();
                                    Context.ImportRsaWrapped(scp03_session, 555, Algorithm.RSA_OAEP_SHA256, Algorithm.MGF1_SHA256, wrapped, new byte[32], ObjectType.PublicWrapKey, 555);
                                    Console.WriteLine(">>>>>");
                                    //usb_session.SendCmd(new SetAttestKeyReq { algorithm = AlgoFromBitLength(crt.Modulus.BitLength), key = q.Concat(p).ToArray() });
                                    //usb_session.SendCmd(new SetAttestCertReq { cert = Scp11Context.GenerateCertificate(pair.Public, pair.Private, "SHA256withRSA").GetEncoded() });
                                    //context.SetDefaultKey(usb_session);
                                    context.PutAuthKey(scp03_session, 2);
                                    using (var scp11_session = context.CreateSession(usb_session, 2))
                                    {
                                        context.GenerateKeyPair("password");
                                        context.ChangeAuthKey(scp11_session, 2);
                                        Context.DeleteObject(scp11_session, 2, ObjectType.AuthenticationKey);
                                        var info2 = scp11_session.SendCmd(HsmCommand.GetDeviceInfo);
                                        Console.WriteLine("DeviceInfo over first scp11_session");
                                        foreach (var b in info2)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                        var rand2 = scp11_session.SendCmd(new GetPseudoRandomReq { length = 64 });
                                        Console.WriteLine("GetPseudoRandom over first scp11_session");
                                        foreach (var b in rand2)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                        context.PutAuthKey(scp03_session, 2);
                                        //context.PutAuthKey(scp11_session, 2);
                                        //context.ChangeAuthKey(scp11_session, 2);
                                    }
                                    using (var scp11_session = context.CreateSession(usb_session, 2))
                                    {
                                        var info2 = scp11_session.SendCmd(HsmCommand.GetDeviceInfo);
                                        Console.WriteLine("DeviceInfo over second scp11_session");
                                        foreach (var b in info2)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                        var rand2 = scp11_session.SendCmd(new GetPseudoRandomReq { length = 64 });
                                        Console.WriteLine("GetPseudoRandom over second scp11_session");
                                        foreach (var b in rand2)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                    }
                                    /*
                                    using (var sess = new Scp03Session(usb_session, 1, scp03_session, 1))
                                    {
                                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                                    }
                                    context.SetClientPubKey(scp03_session);
                                    context.PutAuthKey(scp03_session, 4); // Client pubkey in 4
                                    using(var sess = new Scp11Session(usb_session, 4, scp03_session, 3))
                                    {
                                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                                    }
                                    */
                                }
                            }
                        }
                    }
                }
                var devices = usb_ctx.OpenDevices(d => d.IsYubiHsm, 1).ToList();
                var sessions = devices.Select(d => d.Claim(0)).ToList();
                var scp03_sessions = sessions.Select(s => scp03_context.CreateSession(s, 1)).ToList();
                if(sessions.Count == 2)
                {
                    using (var sess = new Scp03Session(sessions[0], 1, scp03_sessions[1], 1))
                    {
                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                    }

                    using (var sess = new Scp03Session(sessions[1], 1, scp03_sessions[0], 1))
                    {
                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                    }

                    var ctx0 = new Scp11Context(sessions[0]);
                    ctx0.PutAuthKey(scp03_sessions[1], 5); // Device 0 pubkey in device 1 key 5
                    ctx0.SetClientPubKey(scp03_sessions[0]);
                    ctx0.PutAuthKey(scp03_sessions[1], 6); // Client 0 pubkey in device 1 key 6

                    var ctx1 = new Scp11Context(sessions[1]);
                    ctx1.PutAuthKey(scp03_sessions[0], 5); // Device 1 pubkey in device 0 key 5
                    ctx1.SetClientPubKey(scp03_sessions[1]);
                    ctx1.PutAuthKey(scp03_sessions[0], 6); // CLient 1 pubkey in device 0 key 6

                    using (var sess = new Scp11Session(sessions[0], 6, scp03_sessions[1], 5))
                    {
                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                    }

                    using (var sess = new Scp11Session(sessions[1], 6, scp03_sessions[0], 5))
                    {
                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                    }
                }
                scp03_sessions.ForEach(s => s.Dispose());
                sessions.ForEach(s => s.Dispose());
                devices.ForEach(s => s.Dispose());
            }
        }
    }
}
