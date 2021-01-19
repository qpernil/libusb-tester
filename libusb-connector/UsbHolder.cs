using System;
using System.Linq;
using libusb;
using Microsoft.Extensions.Logging;

namespace libusb_connector
{
    public class UsbHolder : IDisposable
    {
        private readonly ILogger<UsbHolder> logger;
        private readonly UsbContext context;
        private UsbDevice device;

        public UsbHolder(ILogger<UsbHolder> logger, UsbContext context)
        {
            this.logger = logger;
            this.context = context;
        }

        public void Dispose()
        {
            device?.Dispose();
        }

        public UsbDevice GetDevice()
        {
            if(device == null || device.SerialNumber == null)
            {
                device?.Dispose();
                device = context.GetDeviceList().Where(d => d.IsYubiHsm).Select(d => context.Open(d, 1)).FirstOrDefault();
            }
            return device;
        }
    }
}
