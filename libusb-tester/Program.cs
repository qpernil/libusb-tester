using System;
using System.IO;
using System.Linq;
using System.Text;
using libusb;

namespace libusb_tester
{
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
        static void Run1(string[] args)
        {
            using (var usb_ctx = new UsbContext())
            {
                var scp03_context = new Scp03Context("password");
                var devices = usb_ctx.OpenDevices(d => d.IsYubiHsm, 1).ToList();
                var sessions = devices.Select(d => d.Claim(0)).ToList();
                var scp03_sessions = sessions.Select(s => scp03_context.CreateSession(s, 1)).ToList();
                scp03_sessions.ForEach(s => s.Dispose());
                sessions.ForEach(s => s.Dispose());
                devices.ForEach(s => s.Dispose());
            }
        }
        static void Run(string[] args)
        {
            //var z = new NSRecord("DFFFFFFFFFFFFFFFFF7F8188818180bb5c424c1b3121cf630cbcbaf60fa91e53786d1ab9e8b6e5855acb9afbec944555481d88fcd8e32947f7696d80a8f4df55be51dcb967fc5ef3d213a971a11fee54917cbe10d4b6ba69a71ee1434ce6b6cadb46ceff0bbf2ba832cb5516af35a1debf182e0a57544a64bfe2d0f711cf94dffb44dda9d1d4a9abdf1460e783b6f18203010001");
            /*
            var x = new PCSC();
            var prc = x.establish_context(PCSC.SCARD_SCOPE_SYSTEM, IntPtr.Zero, IntPtr.Zero, out var pctx);
            var buf = new byte[512];
            int cb = 512;
            prc = x.list_readers(pctx, null, buf, ref cb);
            var s = Encoding.UTF8.GetString(buf[0..cb]);
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
                                //usb_session.SendCmd(HsmCommand.Bsl);
                                //usb_session.SendCmd(new SetFipsDeviceReq { fips = 1 });
                                //usb_session.SendCmd(new SetSerialReq { serial = 12345 });
                                //usb_session.SendCmd(new SetDemoModeReq { demo = 0xffff });
                                var resp = usb_session.SendCmd(HsmCommand.Echo, new byte[] { 1, 2, 3, 4, 5 });

                                using (var scp03_session = scp03_context.CreateSession(usb_session, 1))
                                {
                                    //scp03_session.SendCmd(HsmCommand.Reset);
                                    /*
                                    var res = scp03_session.SendCmd(new PutFipsModeReq { });
                                    var opts = scp03_session.SendCmd(new GetAlgorithmToggleReq { });
                                    for(int i = 1; i < opts.Length; i += 2)
                                    {
                                        opts[i] = 1;
                                    }
                                    res = scp03_session.SendCmd(new PutAlgorithmToggleReq { data = opts.ToArray() });
                                    */
                                    scp03_context.PutOpaque(scp03_session, 0, new byte[254]);
                                    scp03_context.PutAesKey(scp03_session, 4, new byte[16]);
                                    var encrypted = scp03_session.SendCmd(new EncryptEcbReq { key_id = 4, data = new byte[16 * 125] });
                                    var decrypted = scp03_session.EcbCrypt(false, new byte[16], encrypted.ToArray());
                                    var decrypted2 = scp03_session.SendCmd(new DecryptEcbReq { key_id = 4, data = encrypted.ToArray() });
                                    encrypted = scp03_session.SendCmd(new EncryptCbcReq { key_id = 4, iv = new byte[16], data = new byte[16 * 125] });
                                    decrypted = scp03_session.CbcCrypt(false, new byte[16], new byte[16], encrypted.ToArray());
                                    decrypted2 = scp03_session.SendCmd(new DecryptCbcReq { key_id = 4, iv = new byte[16], data = encrypted.ToArray() });
                                    var id = scp03_context.PutEcdhKey(scp03_session, 4);
                                    scp03_context.PutWrapKey(scp03_session, 2, new byte[32]);
                                    scp03_context.ExportWrapped(scp03_session, 2, ObjectType.AsymmetricKey, 4);
                                    scp03_context.ExportWrapped(scp03_session, 2, ObjectType.SymmetricKey, 4);
                                    scp03_context.ExportWrapped(scp03_session, 2, ObjectType.WrapKey, 2);
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
                                    //usb_session.SendCmd(new SetAttestCertReq { cert = context.GenerateCertificate(sk_oce).GetEncoded() });
                                    //context.SetDefaultKey(usb_session);
                                    context.PutAuthKey(scp03_session, 2);
                                    using (var scp11_session = context.CreateSession(usb_session, 2))
                                    {
                                        context.GenerateKeyPair("password");
                                        context.ChangeAuthKey(scp11_session, 2);
                                        context.DeleteObject(scp11_session, 2, ObjectType.AuthenticationKey);
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
                                        var attestation = scp11_session.SendCmd(new AttestAsymmetricReq { key_id = 0, attest_id = 0 });
                                        foreach (var b in attestation)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                        File.WriteAllBytes("attestation.cer", attestation.ToArray());
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
