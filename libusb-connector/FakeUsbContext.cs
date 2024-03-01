using System;
using System.Collections.Generic;
using System.Linq;

namespace libusb_connector
{
    public class FakeUsbContext : IDisposable
    {
        public void Dispose()
        {
        }

        public IEnumerable<FakeUsbDescriptor> GetDeviceList()
        {
            yield return new FakeUsbDescriptor(42, "12345");
            yield return new FakeUsbDescriptor(52, "12346");
        }

        public FakeUsbDevice Open(FakeUsbDescriptor descriptor, int configuration, byte control_endpoint = 0x80)
        {
            return new FakeUsbDevice(descriptor, configuration, control_endpoint);
        }

        public IEnumerable<FakeUsbDevice> OpenDevices(Func<FakeUsbDescriptor, bool> filter, int configuration, byte control_endpoint = 0x80)
        {
            return GetDeviceList().Where(filter).Select(d => Open(d, configuration, control_endpoint));
        }
    }
}