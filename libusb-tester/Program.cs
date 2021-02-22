using System;
using System.IO;
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
                            using (var usb_session = usb_device.Claim(0, 0))
                            {
                                var resp = usb_session.SendCmd(HsmCommand.Echo, new byte[] { 1, 2, 3, 4, 5 });

                                //usb_session.SendCmd(HsmCommand.Bsl);
                                //usb_session.SendCmd(new SetSerialReq { serial = 12345 });

                                using (var scp03_session = new Scp03Context("password").CreateSession(usb_session, 1))
                                {
                                    using (var scp03_sess2 = new Scp03Session(usb_session, 1, scp03_session, 1, new byte[8]))
                                    {
                                        var dinfo = scp03_sess2.SendCmd(HsmCommand.GetDeviceInfo);
                                        Console.WriteLine("DeviceInfo over scp03_sess2");
                                        foreach (var b in dinfo)
                                            Console.Write($"{b:x2}");
                                        Console.WriteLine();
                                    }
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
                                        context.GenerateKeyPair();
                                        context.ChangeAuthKey(scp11_session, 2);
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
            }
        }
    }
}
