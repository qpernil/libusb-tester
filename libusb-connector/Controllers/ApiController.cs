using System;
using System.Collections.Generic;
using System.Linq;
using libusb;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;

namespace libusb_connector.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class ApiController : ControllerBase
    {
        private readonly ILogger<ApiController> _logger;
        private readonly UsbContext _usb;

        public ApiController(ILogger<ApiController> logger, UsbContext usb)
        {
            _logger = logger;
            _usb = usb;
        }

        [HttpGet]
        public IEnumerable<string> Get()
        {
            return Enumerable.Repeat("Api", 3);
        }
    }
}
