using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;

namespace libusb_connector
{
    public class RawOutputFormatter : OutputFormatter
    {
        public RawOutputFormatter()
        {
            SupportedMediaTypes.Add(new MediaTypeHeaderValue("application/octet-stream"));
        }

        protected override bool CanWriteType(Type type)
        {
            return type == typeof(byte[]);
        }

        public async override Task WriteResponseBodyAsync(OutputFormatterWriteContext context)
        {
            await context.HttpContext.Response.Body.WriteAsync((byte[])context.Object, context.HttpContext.RequestAborted);
        }
    }
}
