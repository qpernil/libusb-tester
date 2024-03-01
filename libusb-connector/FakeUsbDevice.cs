using System;
using System.Buffers.Binary;
using libusb;
using Microsoft.Extensions.Logging;

namespace libusb_connector
{
    public class FakeUsbDevice : IDisposable
    {
        private FakeUsbDescriptor descriptor;
        private readonly int config;
        private readonly byte control_endpoint;

        public FakeUsbDevice(FakeUsbDescriptor descriptor, int config, byte control_endpoint)
        {
            this.descriptor = descriptor;
            this.config = config;
            this.control_endpoint = control_endpoint;
        }

        public string SerialNumber => descriptor.serial;

        public void Dispose()
        {
        }

        public FakeUsbSession Claim(int interface_number)
        {
            return new FakeUsbSession(this, interface_number);
        }

        internal void Release(int interface_number)
        {
        }

        private static Span<byte> Error(HsmError code)
        {
            return new byte[] { 0x7f, 0x00, 0x01, (byte)code };
        }

        private static Span<byte> Response(byte code, Span<byte> payload)
        {
            return new byte[] { code };
        }

        internal Span<byte> Transfer(byte[] input, int length)
        {
            try
            {
                var cmd = (HsmCommand)input[0];
                var len = BinaryPrimitives.ReadUInt16BigEndian(input.AsSpan(1, 2));
                var payload = input.AsSpan(3, len);
                Span<byte> response;
                switch (cmd)
                {
                    case HsmCommand.GetDeviceInfo:
                        response = GetDeviceInfo(payload);
                        break;
                    default:
                        return Error(HsmError.INVALID_COMMAND);
                }
                return Response((byte)(input[0] | 0x80), response);
            } catch
            {
                return Error(HsmError.INVALID_DATA);
            }
        }

        private static Span<byte> GetDeviceInfo(Span<byte> payload)
        {
            return new byte[] { 0x86, 0x00, 0x13, 0x02, 0x04, 0x1, 0x01, 0x02, 0x03, 0x04, 62, 12, 0x01, 0x02, 0x03, 0x04, 0x05, 38, 49, 50, 51, 52 };
        }
    }
}