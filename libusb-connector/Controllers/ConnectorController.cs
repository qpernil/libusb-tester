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
        public DeviceInfo(IntPtr id, device_descriptor descriptor)
        {
            this.id = id;
            this.descriptor = descriptor;
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

        private IEnumerable<DeviceInfo> GetDeviceList() => _usb.GetDeviceList().Select(d => new DeviceInfo(d, _usb.GetDeviceDescriptor(d)));

        public ConnectorController(ILogger<ConnectorController> logger, UsbContext usb)
        {
            _logger = logger;
            _usb = usb;
        }

        [HttpGet]
        [Route("devices")]
        public IEnumerable<DeviceInfo> Devices()
        {
            return GetDeviceList();
        }

        private string GetSerial(DeviceInfo info)
        {
            using (var device = _usb.Open(info.id, 1))
            {
                return device.GetStringDescriptor(info.descriptor.iSerialNumber);
            }
        }

        [HttpGet]
        [Route("serials")]
        public IEnumerable<string> Serials()
        {
            return GetDeviceList().Where(i => i.IsYubiHsm).Select(GetSerial);
        }

        [HttpGet]
        [Route("status")]
        public string Status()
        {
            string serial = GetDeviceList().Where(i => i.IsYubiHsm).Select(GetSerial).FirstOrDefault() ?? "*";
            string status = serial == "*" ? "NO_DEVICE" : "OK";
            return $"status={status}\nserial={serial}\nversion=2.2.0\npid=77297\naddress=localhost\nport=12345\n";
        }
        
        [HttpPost]
        [Route("api")]
        public byte[] Api([FromBody] byte[] data)
        {
            var info = GetDeviceList().Where(i => i.IsYubiHsm).First();
            using(var device = _usb.Open(info.id, 1))
            {
                using (var session = device.Claim(0, 0))
                {
                    return session.SendCmd(data).ToArray();
                }
            }
        }
    }
}
