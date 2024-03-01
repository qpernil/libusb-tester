using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using libusb;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace libusb_connector.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ConnectorController : ControllerBase
    {
        private readonly ILogger<ConnectorController> logger;
        private readonly FakeUsbHolder holder;
        private readonly FakeUsbContext usb;

        public ConnectorController(ILogger<ConnectorController> logger, FakeUsbHolder holder, FakeUsbContext usb)
        {
            this.logger = logger;
            this.holder = holder;
            this.usb = usb;
        }

        [HttpGet]
        [Route("devices")]
        public IEnumerable<FakeUsbDescriptor> Devices()
        {
            return usb.GetDeviceList();
        }

        private string GetSerial(FakeUsbDescriptor info)
        {
            using (var device = usb.Open(info, 1))
            {
                return device.SerialNumber;
            }
        }

        [HttpGet]
        [Route("serials")]
        public IEnumerable<string> Serials()
        {
            return usb.GetDeviceList().Where(i => i.IsYubiHsm).Select(GetSerial);
        }

        [HttpGet]
        [Route("status")]
        public string Status()
        {
            string serial = holder.GetDevice()?.SerialNumber ?? "*";
            string status = serial == "*" ? "NO_DEVICE" : "OK";
            return $"status={status}\nserial={serial}\nversion=3.0.0\npid={Process.GetCurrentProcess().Id}\naddress={Request.Host.Host}\nport={Request.Host.Port}\n";
        }
        
        [HttpPost]
        [Route("api")]
        public byte[] Api([FromBody] byte[] data)
        {
            using (var session = holder.GetDevice().Claim(0))
            {
                return session.SendCmd(data).ToArray();
            }
        }
    }
}
