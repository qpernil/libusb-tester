namespace libusb_connector
{
    public class FakeUsbDescriptor
    {
        private long id;
        internal string serial;
        public FakeUsbDescriptor(long id, string serial)
        {
            this.id = id;
            this.serial = serial;
        }
        public long Id => id;
        public ushort Vendor => 0x1050;
        public ushort Product => 0x0030;
        public bool IsYubiHsm => true;
    }
}