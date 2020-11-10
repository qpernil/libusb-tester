using System;
using libusb;

namespace libusb_tester
{
    static class Program
    {
        static void Main(string[] args)
        {
            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    var descriptor = usb_ctx.GetDeviceDescriptor(device);
                    Console.WriteLine($"Id {device} Vendor 0x{descriptor.idVendor:x} Product 0x{descriptor.idProduct:x} Device 0x{descriptor.bcdDevice:x} Usb 0x{descriptor.bcdUSB:x}");
                    if (descriptor.IsYubiHsm())
                    {
                        using (var usb_device = usb_ctx.Open(device))
                        {
                            var manufacturer = usb_device.GetStringDescriptor(descriptor.iManufacturer);
                            var product = usb_device.GetStringDescriptor(descriptor.iProduct);
                            var serial = usb_device.GetStringDescriptor(descriptor.iSerialNumber);
                            Console.WriteLine($"Manufacturer '{manufacturer}' Product '{product}' Serial '{serial}'");
                            using (var usb_session = usb_device.Claim())
                            {
                                //usb_session.SendCmd(HsmCommand.Bsl);
                                //usb_session.SendCmd(new SetSerialReq { serial = 12345 });

                                using (var scp03_session = new Scp03Context("password").CreateSession(usb_session, 1))
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
                                    context.GenerateKeyPair();
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
