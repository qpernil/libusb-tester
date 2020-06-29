using System;

namespace libusb
{
    static class Program
    {
        static void Main(string[] args)
        {
            using (var usb_ctx = new UsbContext())
            {
                foreach (var device in usb_ctx.GetDeviceList())
                {
                    usb_ctx.GetDeviceDescriptor(device, out var descriptor);
                    Console.WriteLine($"Vendor 0x{descriptor.idVendor:x} Product 0x{descriptor.idProduct:x} Device 0x{descriptor.bcdDevice:x} Usb 0x{descriptor.bcdUSB:x}");
                    if (descriptor.idVendor == 0x1050 && descriptor.idProduct == 0x30)
                    {
                        using (var usb_session = usb_ctx.CreateSession(device))
                        {
                            var manufacturer = usb_session.GetStringDescriptor(descriptor.iManufacturer);
                            var product = usb_session.GetStringDescriptor(descriptor.iProduct);
                            var serial = usb_session.GetStringDescriptor(descriptor.iSerialNumber);
                            Console.WriteLine($"Manufacturer '{manufacturer}' Product '{product}' Serial '{serial}'");

                            //usb_session.SendCmd(HsmCommand.Bsl);
                            //usb_session.SendCmd(new SetSerialReq { serial = 12345 });

                            using (var scp03_session = new Scp03Context("password")/*.SetDefaultKey(usb_session)*/.CreateSession(usb_session, 1))
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
                                var context = new Scp11Context(usb_session).PutAuthKey(scp03_session, 2);
                                using (var scp11_session = context.CreateSession(usb_session, 2))
                                {
                                    var info2 = scp11_session.SendCmd(HsmCommand.GetDeviceInfo);
                                    Console.WriteLine("DeviceInfo over scp11_session");
                                    foreach (var b in info2)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var rand2 = scp11_session.SendCmd(new GetPseudoRandomReq { length = 64 });
                                    Console.WriteLine("GetPseudoRandom over scp11_session");
                                    foreach (var b in rand2)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    context.GenerateKey().ChangeAuthKey(scp11_session, 2);
                                }
                                using (var scp11_session = context.CreateSession(usb_session, 2))
                                {
                                    var info2 = scp11_session.SendCmd(HsmCommand.GetDeviceInfo);
                                    Console.WriteLine("DeviceInfo over scp11_session");
                                    foreach (var b in info2)
                                        Console.Write($"{b:x2}");
                                    Console.WriteLine();
                                    var rand2 = scp11_session.SendCmd(new GetPseudoRandomReq { length = 64 });
                                    Console.WriteLine("GetPseudoRandom over scp11_session");
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
