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
            var saved = device;
            if(saved?.SerialNumber == null)
            {
                var created = device = context.GetDeviceList().Where(d => d.IsYubiHsm).Select(d => context.Open(d, 1)).FirstOrDefault();
                saved?.Dispose();
                saved = created;
            }
            return saved;
        }
    }
}
