using System;
using libusb;
using Microsoft.Extensions.Logging;

namespace libusb_connector
{
    public class FakeUsbSession : Session
    {
        private readonly FakeUsbDevice device;
        private readonly int interface_number;

        public FakeUsbSession(FakeUsbDevice device, int interface_number)
        {
            this.device = device;
            this.interface_number = interface_number;
        }

        public override void Dispose()
        {
            device.Release(interface_number);
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            return device.Transfer(input, length);
        }
    }
}