using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
        static void Run(string[] args)
        {
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
                                var resp = usb_session.SendCmd(HsmCommand.Echo, new byte[] { 1, 2, 3, 4, 5 });

                                //usb_session.SendCmd(HsmCommand.Bsl);
                                //usb_session.SendCmd(new SetSerialReq { serial = 12345 });

                                using (var scp03_session = scp03_context.CreateSession(usb_session, 1))
                                {
                                    //scp03_session.SendCmd(HsmCommand.Reset);
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
                                    var sk_oce = context.GenerateKeyPair();
                                    //usb_session.SendCmd(new SetAttestKeyReq { algorithm = 12, buf = sk_oce.D.ToByteArrayFixed() });
                                    //usb_session.SendCmd(new SetAttestCertReq { buf = context.GenerateCertificate(sk_oce).GetEncoded() });
                                    //context.SetDefaultKey(usb_session);
                                    context.PutAuthKey(scp03_session, 2);
                                    using (var scp11_session = context.CreateSession(usb_session, 2))
                                    {
                                        context.GenerateKeyPair("password");
                                        context.ChangeAuthKey(scp11_session, 2);
                                        context.DeleteObject(scp11_session, 2, 2);
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

                    new Scp11Context(sessions[0]).PutAuthKey(scp03_sessions[1], 3);
                    new Scp11Context(sessions[1]).PutAuthKey(scp03_sessions[0], 3);

                    using (var sess = new Scp11Session(sessions[0], 3, scp03_sessions[1], 3))
                    {
                        sess.SendCmd(new GetPseudoRandomReq { length = 64 });
                    }

                    using (var sess = new Scp11Session(sessions[1], 3, scp03_sessions[0], 3))
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
