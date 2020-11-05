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
        public DeviceInfo(IntPtr idx, device_descriptor descriptor)
        {
            Index = idx.ToInt64();
            Vendor = descriptor.idVendor;
            Product = descriptor.idProduct;
        }

        public long Index { get; }
        public ushort Vendor { get; }
        public ushort Product { get; }
    }

    public static class Extensions
    {
        public static bool IsYubiHsm(this device_descriptor d)
        {
            return d.idVendor == 0x1050 && d.idProduct == 0x30;
        }
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
            return _usb.GetDeviceList().Select(i => new DeviceInfo(i, _usb.GetDeviceDescriptor(i)));
        }

        [HttpGet]
        [Route("status")]
        public string Status()
        {
            return "status=OK\nserial=*\nversion=2.2.0\npid=77297\naddress=localhost\nport=12345\n";
        }

        [HttpPost]
        [Route("api")]
        public byte[] Api([FromBody] byte[] data)
        {
            var device = _usb.GetDeviceList().Where(d => _usb.GetDeviceDescriptor(d).IsYubiHsm()).First();
            using(var session = _usb.CreateSession(device)) {
                return session.SendCmd(data).ToArray();
            }
        }
    }
}
