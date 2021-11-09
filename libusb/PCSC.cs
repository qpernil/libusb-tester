using System;

namespace libusb
{
    public class PCSC
    {
        public delegate uint SCardEstablishContext(uint scope, IntPtr reserved1, IntPtr reserved2, out IntPtr ctx);

        public delegate uint SCardReleaseContext(IntPtr ctx);

        public delegate uint SCardListReaders(IntPtr ctx, string groups, byte[] readers, ref int cb_readers);

        private readonly SafeNativeLibrary pcsc;
        public readonly SCardEstablishContext establish_context;
        public readonly SCardReleaseContext release_context;
        public readonly SCardListReaders list_readers;

        public const uint SCARD_SCOPE_SYSTEM = 2;

        public PCSC(string libraryPath = "/System/Library/Frameworks/PCSC.framework/PCSC")
        {
            pcsc = new SafeNativeLibrary(libraryPath);
            pcsc.GetExport(out establish_context);
            pcsc.GetExport(out release_context);
            pcsc.GetExport(out list_readers);
        }
    }
}
