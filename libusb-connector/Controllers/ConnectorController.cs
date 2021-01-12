﻿using System.Collections.Generic;
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
        private readonly ILogger<ConnectorController> _logger;
        private readonly UsbContext _usb;

        public ConnectorController(ILogger<ConnectorController> logger, UsbContext usb)
        {
            _logger = logger;
            _usb = usb;
        }

        [HttpGet]
        [Route("devices")]
        public IEnumerable<UsbDescriptor> Devices()
        {
            return _usb.GetDeviceList();
        }

        private string GetSerial(UsbDescriptor info)
        {
            using (var device = _usb.Open(info, 1))
            {
                return device.SerialNumber;
            }
        }

        [HttpGet]
        [Route("serials")]
        public IEnumerable<string> Serials()
        {
            return _usb.GetDeviceList().Where(i => i.IsYubiHsm).Select(GetSerial);
        }

        [HttpGet]
        [Route("status")]
        public string Status()
        {
            string serial = _usb.GetDeviceList().Where(i => i.IsYubiHsm).Select(GetSerial).FirstOrDefault() ?? "*";
            string status = serial == "*" ? "NO_DEVICE" : "OK";
            return $"status={status}\nserial={serial}\nversion=2.2.0\npid={Process.GetCurrentProcess().Id}\naddress={Request.Host.Host}\nport={Request.Host.Port}\n";
        }
        
        [HttpPost]
        [Route("api")]
        public byte[] Api([FromBody] byte[] data)
        {
            using(var device = _usb.GetDeviceList().Where(i => i.IsYubiHsm).Select(d => _usb.Open(d, 1)).First())
            {
                using (var session = device.Claim(0, 0))
                {
                    return session.SendCmd(data).ToArray();
                }
            }
        }
    }
}
