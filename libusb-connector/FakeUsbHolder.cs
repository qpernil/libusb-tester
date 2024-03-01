using System;
using System.Linq;
using Microsoft.Extensions.Logging;

namespace libusb_connector
{
    public class FakeUsbHolder : IDisposable
    {
        private readonly ILogger<FakeUsbHolder> logger;
        private readonly FakeUsbContext context;
        private FakeUsbDevice device;

        public FakeUsbHolder(ILogger<FakeUsbHolder> logger, FakeUsbContext context)
        {
            this.logger = logger;
            this.context = context;
        }

        public void Dispose()
        {
            device.Dispose();
        }

        public FakeUsbDevice GetDevice()
        {
            var saved = device;
            if (saved?.SerialNumber == null)
            {
                var created = device = context.OpenDevices(d => d.IsYubiHsm, 1).FirstOrDefault();
                saved?.Dispose();
                saved = created;
            }
            return saved;
        }
    }
}
