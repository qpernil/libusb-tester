using System;
using System.Buffers.Binary;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading;
using libusb;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Crypto.Encodings;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.X509;

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
        static int get_padded_len(byte[] thisPin, byte padding = 0xff) {
            int len = thisPin.Length;
            for (; len > 0; len--) {
                if (thisPin[len - 1] != padding) {
                    Console.WriteLine($"Last non-padding char found at {len}");
                    break;
                }
            }
            return len;
        }
        static int get_padded_len2(byte[] thisPin, byte padding = 0xff)
        {
            int len = thisPin.Length;
            for (int i = 0; i < thisPin.Length; i++)
            {
                if (thisPin[i] == padding)
                {
                    if(i < len)
                    {
                        Console.WriteLine($"First padding char found at {i}");
                        len = i;
                    }
                } else
                {
                    if(i > len)
                    {
                        Console.WriteLine($"Invalid padding at {i}");
                        return 0;
                    }
                }
            }
            return len;
        }
        static int count_utf8_points(byte[] str)
        {
            int i, points = 0;
            for (i = 0; i < str.Length; i++)
            {
                points++;
                switch (str[i] & 0xf0) {
                    case 0xf0:
                        //Console.WriteLine($"4 byte codepoint {str[i]:b8} at {i}");
                        i += 3;
                        break;
                    case 0xe0:
                        //Console.WriteLine($"3 byte codepoint {str[i]:b8} at {i}");
                        i += 2;
                        break;
                    case 0xc0:
                        //Console.WriteLine($"2 byte codepoint {str[i]:b8} at {i}");
                        i += 1;
                        break;
                    default:
                        //Console.WriteLine($"1 byte codepoint {str[i]:b8} at {i}");
                        break;
                }
                if (i >= str.Length)
                {
                    //Console.WriteLine($"Incomplete code point at {str.Length}, rejected");
                    return 0;
                }
            }
            return points;
        }
        static int count_utf8_points2(byte[] str) {
            int i, points = 0, continuation = 0;
            for (i = 0; i < str.Length; i++) {
                if(continuation > 0)
                {
                    if ((str[i] & 0xc0) == 0x80)
                    { // Continuation bytes begin with 0b10
                        //Console.WriteLine($"Valid continuation byte {str[i]:b8} at {i}");
                        continuation--;
                    }
                    else
                    {
                        //Console.WriteLine($"Invalid continuation byte {str[i]:b8} at {i}");
                        return 0;
                    }
                }
                else
                {
                    points++;
                    if ((str[i] & 0xf8) == 0xf0)
                    { // 4 byte code points begin with 0b11110
                        //Console.WriteLine($"4 byte code point {str[i]:b8} at {i}");
                        continuation = 3;
                    }
                    else if ((str[i] & 0xf0) == 0xe0)
                    { // 3 byte code points begin with 0b1110
                        //Console.WriteLine($"3 byte code point {str[i]:b8} at {i}");
                        continuation = 2;
                    }
                    else if ((str[i] & 0xe0) == 0xc0)
                    { // 2 byte code points begin with 0b110
                        //Console.WriteLine($"2 byte code point {str[i]:b8} at {i}");
                        continuation = 1;
                    }
                    else if ((str[i] & 0x80) == 0x80)
                    { // 1 byte code points must begin with 0xb0
                        //Console.WriteLine($"Invalid initial byte {str[i]:b8} at {i}");
                        return 0;
                    } else
                    {
                        //Console.WriteLine($"1 byte code point {str[i]:b8} at {i}");
                    }
                }
            }
            if(continuation > 0)
            {
                //Console.WriteLine($"Incomplete code point at {i}");
                return 0;
            }
            else
            {
                return points;
            }
        }
        static string test_utf8_points(byte[] bytes)
        {
            var enc = new UTF8Encoding(false, true);
            var s = new MemoryStream();
            using (TextWriter w = new StreamWriter(s, enc))
            {
                w.Write($"test_utf8_points ({bytes.Length}) ");
                if(bytes.Length < 16)
                {
                    for (int i = 0; i < bytes.Length; i++)
                    {
                        w.Write($"0x{bytes[i]:x2}, ");
                    }
                }
                var count = count_utf8_points(bytes);
                var count2 = count_utf8_points2(bytes);
                w.Write($"count_utf8_points: {count} count_utf8_points2: {count2} {count == count2}");
            }
            return enc.GetString(s.ToArray());
        }
        static string test_utf8_points(string str)
        {
            return test_utf8_points(Encoding.UTF8.GetBytes(str));
        }
        static void Run0(string[] args)
        {
            var scp03_context = new Scp03Context("password");
            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    //Console.WriteLine($"Id {device.Id} Vendor 0x{device.Vendor:x} Product 0x{device.Product:x}");
                    if (device.IsYubiHsm)
                    {
                        using (var usb_device = usb_ctx.Open(device, device.Configuration))
                        {
                            //Console.WriteLine($"Manufacturer '{usb_device.Manufacturer}' Product '{usb_device.Product}' Serial '{usb_device.SerialNumber}'");
                            using (var usb_session = usb_device.Claim(0))
                            {
                                using (var scp03_session = scp03_context.CreateSession(usb_session, 1))
                                {
                                    var fred_id = Context.GenerateX25519Key(scp03_session, 11);
                                    var fred_pub = Context.GetPubKey(scp03_session, 11, out var fred_algo).ToArray();

                                    var alice_priv = Convert.FromHexString("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
                                    var alice_id = Context.PutX25519Key(scp03_session, 9, alice_priv);
                                    var alice_pub = Context.GetPubKey(scp03_session, 9, out var alice_algo).ToArray();
                                    var alice_ref = Convert.FromHexString("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a");

                                    var bob_priv = Convert.FromHexString("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb");
                                    var bob_id = Context.PutX25519Key(scp03_session, 10, bob_priv);
                                    var bob_pub = Context.GetPubKey(scp03_session, 10, out var bob_algo).ToArray();
                                    var bob_ref = Convert.FromHexString("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f");

                                    var alice_sec = Context.DecryptEcdh(scp03_session, 9, bob_pub).ToArray();
                                    var bob_sec = Context.DecryptEcdh(scp03_session, 10, alice_pub).ToArray();

                                    var ref_sec = Convert.FromHexString("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");

                                    var alice_fred_sec = Context.DecryptEcdh(scp03_session, 9, fred_pub).ToArray();
                                    var fred_alice_sec = Context.DecryptEcdh(scp03_session, 11, alice_pub).ToArray();

                                    Console.WriteLine();

                                    Console.Write($"alice_priv ({alice_algo}): ");
                                    foreach (var b in alice_priv)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write($"alice_pub ({alice_algo}): ");
                                    foreach (var b in alice_pub)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write($"alice_ref ({alice_algo}): ");
                                    foreach (var b in alice_ref)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.WriteLine();

                                    Console.Write($"bob_priv ({bob_algo}): ");
                                    foreach (var b in bob_priv)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write($"bob_pub ({bob_algo}): ");
                                    foreach (var b in bob_pub)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write($"bob_ref ({bob_algo}): ");
                                    foreach (var b in bob_ref)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.WriteLine();

                                    Console.Write("alice_sec: ");
                                    foreach (var b in alice_sec)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write("bob_sec: ");
                                    foreach (var b in bob_sec)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write("ref_sec: ");
                                    foreach (var b in ref_sec)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.WriteLine();

                                    Console.Write("alice_fred_sec: ");
                                    foreach (var b in alice_fred_sec)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();

                                    Console.Write("fred_alice_sec: ");
                                    foreach (var b in fred_alice_sec)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    Console.WriteLine();

                                    var factories = new Pkcs11InteropFactories();
                                    using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, "/usr/local/lib/libykcs11.dylib", AppType.SingleThreaded))
                                    {
                                        Console.WriteLine($"{lib.GetInfo().ManufacturerId} {lib.GetInfo().LibraryDescription}");
                                        foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                                        {
                                            Console.WriteLine($"{slot.GetTokenInfo().Label}");
                                            using (var s = slot.OpenSession(SessionType.ReadWrite))
                                            {
                                                s.Login(CKU.CKU_USER, "123456");

                                                var keys = s.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, 0x41),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 253),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)});

                                                if (keys.Count > 0)
                                                {
                                                    var label = s.GetAttributeValue(keys[0], new List<CKA> { CKA.CKA_LABEL })[0].GetValueAsString();
                                                    Console.WriteLine($"{label}");
                                                    var bytes = s.GetAttributeValue(keys[0], new List<CKA> { CKA.CKA_EC_POINT })[0].GetValueAsByteArray();
                                                    var octetString = (Asn1OctetString)Asn1Object.FromByteArray(bytes);
                                                    var yubikey_pub = octetString.GetOctets();

                                                    var mech = factories.MechanismFactory.Create(CKM.CKM_ECDH1_DERIVE,
                                                        factories.MechanismParamsFactory.CreateCkEcdh1DeriveParams((ulong)CKD.CKD_NULL, null, fred_pub));

                                                    var obj = s.DeriveKey(mech, keys[0], new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false)});

                                                    var value = s.GetAttributeValue(obj, new List<CKA> { CKA.CKA_VALUE });
                                                    var yubikey_fred_sec = value[0].GetValueAsByteArray();

                                                    s.DestroyObject(obj);

                                                    var fred_yubikey_sec = Context.DecryptEcdh(scp03_session, 11, yubikey_pub).ToArray();

                                                    Console.WriteLine();

                                                    Console.Write("yubikey_fred_sec: ");
                                                    foreach (var b in yubikey_fred_sec)
                                                        Console.Write($"{b:x2}");
                                                    Console.WriteLine();

                                                    Console.Write("fred_yubikey_sec: ");
                                                    foreach (var b in fred_yubikey_sec)
                                                        Console.Write($"{b:x2}");
                                                    Console.WriteLine();

                                                    Console.WriteLine();

                                                    break;
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        static void Run(string[] args)
        {
            /*
            Console.WriteLine("get_padded_len");
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 5, 6, 7, 0xff }));
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 5, 6, 0xff, 0xff }));
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 5, 0xff, 0xff, 0xff }));
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 5, 0xff, 7, 0xff }));
            Console.WriteLine(get_padded_len(new byte[] { 1, 2, 3, 4, 0xff, 6, 7, 0xff }));
            Console.WriteLine();

            Console.WriteLine("get_padded_len2");
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 5, 6, 7, 0xff }));
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 5, 6, 0xff, 0xff }));
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 5, 0xff, 0xff, 0xff }));
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 5, 0xff, 7, 0xff }));
            Console.WriteLine(get_padded_len2(new byte[] { 1, 2, 3, 4, 0xff, 6, 7, 0xff }));
            Console.WriteLine();

            Console.WriteLine(test_utf8_points(new byte[] { 0 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0x7f }));
            Console.WriteLine(test_utf8_points(new byte[] { 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xc0 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xc0, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xa0, 0xa1 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xc3, 0xbf }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xc3, 0x28 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xdf, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xdf, 0xbf }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xdf, 0xdf }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xe0, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xe0, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xef, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf0, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xef, 0xbf, 0xbe }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xef, 0xbf, 0xbf }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xe2, 0x82, 0xa1 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xe2, 0x28, 0xa1 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xe2, 0x82, 0x28 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf0, 0x80, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf7, 0x80, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf8, 0x80, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xff, 0x80, 0x80, 0x80 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf0, 0x90, 0x8c, 0xbc }));
            Console.WriteLine(test_utf8_points(new byte[] { 0x31, 0x32, 0x33, 0x34, 0xdf, 0xbf }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xf0, 0x9f, 0x92, 0xa9, 0xf0, 0x9f, 0x92, 0xa9 }));
            Console.WriteLine(test_utf8_points(new byte[] { 0xdf, 0xbf }));
            Console.WriteLine();

            Console.WriteLine(test_utf8_points("abc"));
            Console.WriteLine(test_utf8_points("åäö"));
            Console.WriteLine(test_utf8_points("pölsa"));
            Console.WriteLine(test_utf8_points("κόσμε")); // Greek letters
            Console.WriteLine();

            // Some tests from https://kermitproject.org/utf8.html
            Console.WriteLine(test_utf8_points("Τὴ γλῶσσα μοῦ ἔδωσαν ἑλληνικὴ\nτὸ σπίτι φτωχικὸ στὶς ἀμμουδιὲς τοῦ Ὁμήρου.\nΜονάχη ἔγνοια ἡ γλῶσσα μου στὶς ἀμμουδιὲς τοῦ Ὁμήρου.\nἀπὸ τὸ Ἄξιον ἐστί\nτοῦ Ὀδυσσέα Ἐλύτη"));
            Console.WriteLine(test_utf8_points("Τη γλώσσα μου έδωσαν ελληνική\nτο σπίτι φτωχικό στις αμμουδιές του Ομήρου.\nΜονάχη έγνοια η γλώσσα μου στις αμμουδιές του Ομήρου.\nαπό το Άξιον Εστί\nτου Οδυσσέα Ελύτη"));
            Console.WriteLine(test_utf8_points("Sîne klâwen durh die wolken sint geslagen,\ner stîget ûf mit grôzer kraft,\nich sih in grâwen tägelîch als er wil tagen,\nden tac, der im geselleschaft\nerwenden wil, dem werden man,\nden ich mit sorgen în verliez.\nich bringe in hinnen, ob ich kan.\nsîn vil manegiu tugent michz leisten hiez."));
            Console.WriteLine(test_utf8_points("An preost wes on leoden, Laȝamon was ihoten\nHe wes Leovenaðes sone -- liðe him be Drihten.\nHe wonede at Ernleȝe at æðelen are chirechen,\nUppen Sevarne staþe, sel þar him þuhte,\nOnfest Radestone, þer he bock radde."));
            Console.WriteLine(test_utf8_points("ᚠᛇᚻ᛫ᛒᛦᚦ᛫ᚠᚱᚩᚠᚢᚱ᛫ᚠᛁᚱᚪ᛫ᚷᛖᚻᚹᛦᛚᚳᚢᛗ\nᛋᚳᛖᚪᛚ᛫ᚦᛖᚪᚻ᛫ᛗᚪᚾᚾᚪ᛫ᚷᛖᚻᚹᛦᛚᚳ᛫ᛗᛁᚳᛚᚢᚾ᛫ᚻᛦᛏ᛫ᛞᚫᛚᚪᚾ\nᚷᛁᚠ᛫ᚻᛖ᛫ᚹᛁᛚᛖ᛫ᚠᚩᚱ᛫ᛞᚱᛁᚻᛏᚾᛖ᛫ᛞᚩᛗᛖᛋ᛫ᚻᛚᛇᛏᚪᚾ"));
            Console.WriteLine(test_utf8_points("ვეპხის ტყაოსანი შოთა რუსთაველი\nღმერთსი შემვედრე, ნუთუ კვლა დამხსნას სოფლისა შრომასა, ცეცხლს, წყალსა და მიწასა, ჰაერთა თანა მრომასა; მომცნეს ფრთენი და აღვფრინდე, მივჰხვდე მას ჩემსა ნდომასა, დღისით და ღამით ვჰხედვიდე მზისა ელვათა კრთომაასა."));
            Console.WriteLine(test_utf8_points("யாமறிந்த மொழிகளிலே தமிழ்மொழி போல் இனிதாவது எங்கும் காணோம்,\nபாமரராய் விலங்குகளாய், உலகனைத்தும் இகழ்ச்சிசொலப் பான்மை கெட்டு,\nநாமமது தமிழரெனக் கொண்டு இங்கு வாழ்ந்திடுதல் நன்றோ? சொல்லீர்!\nதேமதுரத் தமிழோசை உலகமெலாம் பரவும்வகை செய்தல் வேண்டும்.\n"));
            Console.WriteLine(test_utf8_points("ಬಾ ಇಲ್ಲಿ ಸಂಭವಿಸು ಇಂದೆನ್ನ ಹೃದಯದಲಿ\nನಿತ್ಯವೂ ಅವತರಿಪ ಸತ್ಯಾವತಾರ\nಮಣ್ಣಾಗಿ ಮರವಾಗಿ ಮಿಗವಾಗಿ ಕಗವಾಗೀ...\nಮಣ್ಣಾಗಿ ಮರವಾಗಿ ಮಿಗವಾಗಿ ಕಗವಾಗಿ\nಭವ ಭವದಿ ಭತಿಸಿಹೇ ಭವತಿ ದೂರ\nನಿತ್ಯವೂ ಅವತರಿಪ ಸತ್ಯಾವತಾರ || ಬಾ ಇಲ್ಲಿ ||"));
            Console.WriteLine();
            */

            //var z = new NSRecord("DFFFFFFFFFFFFFFFFF7F8188818180bb5c424c1b3121cf630cbcbaf60fa91e53786d1ab9e8b6e5855acb9afbec944555481d88fcd8e32947f7696d80a8f4df55be51dcb967fc5ef3d213a971a11fee54917cbe10d4b6ba69a71ee1434ce6b6cadb46ceff0bbf2ba832cb5516af35a1debf182e0a57544a64bfe2d0f711cf94dffb44dda9d1d4a9abdf1460e783b6f18203010001");
            /*
            var x = new PCSC("/Users/PNilsson/Firmware/YkPlus/yubi-ifx-common/sim/ykplus/build/libykplus-pcsc.dylib");
            var prc = x.establish_context(PCSC.SCARD_SCOPE_SYSTEM, nint.Zero, nint.Zero, out var pctx);
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
                    Console.WriteLine($"Id {device.Id} Vendor 0x{device.Vendor:x} Product 0x{device.Product:x} Configuration {device.Configuration} IsCCID {device.IsCCID}");
                    if (device.IsYubiHsm)
                    {
                        using (var usb_device = usb_ctx.Open(device, device.Configuration))
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
                                    scp03_session.SendCmd(new GetForcedAuditReq());
                                    scp03_session.SendCmd(new GetCommandAuditReq());
                                    //var x = File.ReadAllBytes("/Users/pnilsson/Downloads/pubkey3.bin");
                                    //scp03_session.Transfer(x, x.Length);
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
                                    */
                                    //var res = scp03_session.SendCmd(new PutFipsModeReq { fips = 1 });
                                    /*
                                    var fips = scp03_session.SendCmd(new GetFipsModeReq { });
                                    Console.WriteLine("GetFipsMode over scp03_session");
                                    foreach (var b in fips)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    */
                                    Context.PutAesKey(scp03_session, 4, new byte[16]);
                                    var encrypted = scp03_session.SendCmd(new EncryptEcbReq { key_id = 4, data = new byte[16*125] });
                                    var decrypted = scp03_session.EcbCrypt(false, new byte[16], encrypted.ToArray());
                                    var decrypted2 = scp03_session.SendCmd(new DecryptEcbReq { key_id = 4, data = encrypted.ToArray() });

                                    Debug.Assert(decrypted.SequenceEqual(decrypted2.ToArray()));

                                    encrypted = scp03_session.SendCmd(new EncryptCbcReq { key_id = 4, iv = new byte[16], data = new byte[16 * 125] });
                                    decrypted = scp03_session.CbcCrypt(false, new byte[16], new byte[16], encrypted.ToArray());
                                    decrypted2 = scp03_session.SendCmd(new DecryptCbcReq { key_id = 4, iv = new byte[16], data = encrypted.ToArray() });

                                    Debug.Assert(decrypted.SequenceEqual(decrypted2.ToArray()));
                                    /*
                                    var encrypted2 = scp03_session.SendCmd(new WrapKwpReq { key_id = 4, data = new byte[3000] });
                                    var decrypted3 = scp03_session.SendCmd(new UnwrapKwpReq { key_id = 4, data = encrypted2.ToArray() });

                                    File.WriteAllBytes("kwp-wrapped", encrypted2.ToArray());
                                    File.WriteAllBytes("kwp-unwrapped", decrypted3.ToArray());
                                    
                                    Console.Write($"/opt/homebrew/opt/openssl@3/bin/openssl enc -d -id-aes128-wrap-pad -iv A65959A6 -K ");
                                    foreach (var b in new byte[16])
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine(" -in kwp-wrapped -out openssl-unwrapped");

                                    Console.WriteLine($"KWP wrapped data {encrypted2.Length}");
                                    foreach (var b in encrypted2.ToArray())
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    Console.WriteLine($"KWP unwrapped data {decrypted3.Length}");
                                    foreach (var b in decrypted3.ToArray())
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    */
                                    var key = new byte[] {
                    //                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    //                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    //                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                    //                    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00,
                                        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
                                        0xbc, 0xe6, 0xfa, 0xad, 0xa7, 0x17, 0x9e, 0x84,
                                        0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x50-8
                                    };
                                    var id = Context.PutEcP256Key(scp03_session, 5, key);
                                    Context.SignEcdsa(scp03_session, 5);
                                    var id2 = Context.PutEd25519Key(scp03_session, 6, key);
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
                                    var id5 = Context.GenerateX25519Key(scp03_session, 9);
                                    var pub5 = Context.GetPubKey(scp03_session, 9, out algo).ToArray();
                                    Console.WriteLine(algo);
                                    Console.Write("pub5: ");
                                    foreach (var b in pub5)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var id6  = Context.GenerateX25519Key(scp03_session, 10);
                                    var pub6 = Context.GetPubKey(scp03_session, 10, out algo).ToArray();
                                    Console.WriteLine(algo);
                                    var sec1 = Context.DecryptEcdh(scp03_session, 9, pub6).ToArray();
                                    var sec2 = Context.DecryptEcdh(scp03_session, 10, pub5).ToArray();
                                    Console.Write("sec1: ");
                                    foreach (var b in sec1)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    Console.Write("sec2: ");
                                    foreach (var b in sec2)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
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
                                    var attcert = new X509Certificate(scp03_session.SendCmd(new GetOpaqueReq { object_id = 0 }).ToArray());
                                    File.WriteAllBytes("attestation.cer", attcert.GetEncoded());
                                    var attestation = new X509Certificate(scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 9, attest_id = 0 }).ToArray());
                                    File.WriteAllBytes("attestation9.cer", attestation.GetEncoded());
                                    var pair = Scp11Context.GenerateRsaKeyPair(2048);
                                    var rsa = (RsaKeyParameters)pair.Public;
                                    var crt = (RsaPrivateCrtKeyParameters)pair.Private;
                                    var p = crt.P.ToByteArrayUnsigned();
                                    var q = crt.Q.ToByteArrayUnsigned();
                                    var n = crt.Modulus.ToByteArrayUnsigned();
                                    Context.PutRsaKey(scp03_session, 4, AlgoFromBitLength(crt.Modulus.BitLength), p.Concat(q).ToArray());
                                    var engine = new Pkcs1Encoding(new RsaEngine());
                                    engine.Init(true, rsa);
                                    var encrypted2 = engine.ProcessBlock(new byte[100], 0, 100);
                                    Console.WriteLine($"***** p {p.Length} q {q.Length} n {n.Length}");
                                    var decrypted3 = scp03_session.SendCmd(new DecryptPkcs1Req { key_id = 4, data = encrypted2 }).ToArray();
                                    Console.WriteLine("*****");
                                    attestation = new X509Certificate(scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 0, attest_id = 0 }).ToArray());
                                    File.WriteAllBytes("attestation0.cer", attestation.GetEncoded());
                                    attestation.Verify(attcert.GetPublicKey());
                                    var attcert4 = new X509Certificate(scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 4, attest_id = 0 }).ToArray());
                                    attcert4.Verify(attcert.GetPublicKey());
                                    Context.PutOpaque(scp03_session, 4, Algorithm.OPAQUE_X509_CERT, attcert4.GetEncoded());
                                    attestation = new X509Certificate(scp03_session.SendCmd(new AttestAsymmetricReq { key_id = 4, attest_id = 4 }).ToArray());
                                    attestation.Verify(attcert4.GetPublicKey());
                                    File.WriteAllBytes("attestation4.cer", attcert4.GetEncoded());
                                    Context.SignPkcs1(scp03_session, 4);
                                    Context.SignPss(scp03_session, 4, Algorithm.MGF1_SHA256, new byte[32]);
                                    Console.WriteLine($"<<<<< p {p.Length} q {q.Length} n {n.Length}");
                                    Context.PutWrapKey(scp03_session, 555, AlgoFromBitLength(crt.Modulus.BitLength), p.Concat(q).ToArray());
                                    Context.PutPublicWrapKey(scp03_session, 555, AlgoFromBitLength(rsa.Modulus.BitLength), n);
                                    var wrapped = Context.ExportWrapped(scp03_session, 2, ObjectType.PublicWrapKey, 555).ToArray();
                                    Context.ImportWrapped(scp03_session, 2, wrapped, ObjectType.PublicWrapKey, 555);
                                    wrapped = Context.ExportRsaWrapped(scp03_session, 555, ObjectType.PublicWrapKey, 555, Algorithm.AES_256, Algorithm.RSA_OAEP_SHA256, Algorithm.MGF1_SHA256, new byte[32]).ToArray();
                                    Context.ImportRsaWrapped(scp03_session, 555, Algorithm.RSA_OAEP_SHA256, Algorithm.MGF1_SHA256, wrapped, new byte[32], ObjectType.PublicWrapKey, 555);
                                    using (var decr = new Pkcs11RsaDecryptor("123456", 2048))
                                    {
                                        var modulus = decr.GetModulus();
                                        Context.PutPublicWrapKey(scp03_session, 556, AlgoFromBitLength(modulus.Length * 8), modulus);
                                        wrapped = Context.GetRsaWrapped(scp03_session, 556, ObjectType.AsymmetricKey, 4, Algorithm.AES_256, Algorithm.RSA_OAEP_SHA256, Algorithm.MGF1_SHA256, new byte[32]).ToArray();
                                    }
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
