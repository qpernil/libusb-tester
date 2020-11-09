using System;
using System.Collections.Generic;
using System.Linq;
using libusb;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace libusb_connector.Controllers
{
    public class DeviceInfo
    {
        public DeviceInfo(UsbContext usb, IntPtr id)
        {
            this.id = id;
            this.descriptor = usb.GetDeviceDescriptor(id);
        }

        internal IntPtr id;
        internal device_descriptor descriptor;

        public long Id => id.ToInt64();
        public bool IsYubiHsm => descriptor.IsYubiHsm();
        public ushort Vendor => descriptor.idVendor;
        public ushort Product => descriptor.idProduct;
    }

    [ApiController]
    [Route("[controller]")]
    public class ConnectorController : ControllerBase
    {
        private readonly ILogger<ConnectorController> _logger;
        private readonly UsbContext _usb;

        public ConnectorController(ILogger<ConnectorController> logger, UsbContext usb)
        {
            _logger = logger;
            _usb = usb;
        }

        [HttpGet]
        [Route("devices")]
        public IEnumerable<DeviceInfo> Devices()
        {
            return _usb.GetDeviceList().Select(d => new DeviceInfo(_usb, d));
        }

        private string GetSerial(DeviceInfo info)
        {
            using (var session = _usb.CreateSession(info.id))
            {
                return session.GetStringDescriptor(info.descriptor.iSerialNumber);
            }
        }

        [HttpGet]
        [Route("serials")]
        public IEnumerable<string> Serials()
        {
            return _usb.GetDeviceList().Select(d => new DeviceInfo(_usb, d)).Where(i => i.IsYubiHsm).Select(GetSerial);
        }

        [HttpGet]
        [Route("status")]
        public string Status()
        {
            string serial = _usb.GetDeviceList().Select(d => new DeviceInfo(_usb, d)).Where(i => i.IsYubiHsm).Select(GetSerial).FirstOrDefault() ?? "*";
            string status = serial == "*" ? "NO_DEVICE" : "OK";
            return $"status={status}\nserial={serial}\nversion=2.2.0\npid=77297\naddress=localhost\nport=12345\n";
        }

        [HttpPost]
        [Route("api")]
        public byte[] Api([FromBody] byte[] data)
        {
            var device = _usb.GetDeviceList().Where(d => _usb.GetDeviceDescriptor(d).IsYubiHsm()).First();
            using(var session = _usb.CreateSession(device))
            {
                return session.SendCmd(data).ToArray();
            }
        }
    }
}
