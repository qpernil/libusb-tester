using System;
using System.IO;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc.Formatters;
using Microsoft.Net.Http.Headers;

namespace libusb_connector
{
    public class RawInputFormatter : InputFormatter
    {
        public RawInputFormatter()
        {
            SupportedMediaTypes.Add(new MediaTypeHeaderValue("application/octet-stream"));
        }

        protected override bool CanReadType(Type type)
        {
            return type == typeof(byte[]);
        }

        public async override Task<InputFormatterResult> ReadRequestBodyAsync(InputFormatterContext context)
        {
            var ms = new MemoryStream(2048 + 3);
            await context.HttpContext.Request.Body.CopyToAsync(ms, context.HttpContext.RequestAborted);
            return InputFormatterResult.Success(ms.ToArray());
        }
    }
}
