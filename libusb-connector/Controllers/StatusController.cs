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

    [ApiController]
    [Route("[controller]")]
    public class StatusController : ControllerBase
    {
        private readonly ILogger<StatusController> _logger;
        private readonly UsbContext _usb;

        public StatusController(ILogger<StatusController> logger, UsbContext usb)
        {
            _logger = logger;
            _usb = usb;
        }

        [HttpGet]
        public string Get()
        {
            return "This is it";
        }

        [HttpGet]
        [Route("usb")]
        public IEnumerable<DeviceInfo> GetUsb()
        {
            return _usb.GetDeviceList().Select(i => new DeviceInfo(i, _usb.GetDeviceDescriptor(i)));
        }
    }
}
