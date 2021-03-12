using System;
using System.Net.Http;

namespace libusb
{
    public class HttpSession : Session
    {
        public HttpSession(string baseAddress)
        {
            client = new HttpClient() { BaseAddress = new Uri(new Uri(baseAddress), new Uri("connector/", UriKind.Relative)) };
            _ = client.GetStringAsync("status").Result;
        }

        public override void Dispose()
        {
            client.Dispose();
        }

        public override Span<byte> Transfer(byte[] input, int length)
        {
            var res = client.PostAsync("api", new ByteArrayContent(input, 0, length)).Result;
            return res.Content.ReadAsByteArrayAsync().Result;
        }

        private readonly HttpClient client;
    }
}
