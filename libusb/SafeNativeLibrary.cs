using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace libusb
{
    public class SafeNativeLibrary : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeLibrary(string libraryPath) : base(true)
        {
            handle = NativeLibrary.Load(libraryPath, GetType().Assembly, DllImportSearchPath.LegacyBehavior);
        }
        protected override bool ReleaseHandle()
        {
            NativeLibrary.Free(handle);
            return true;
        }
        public IntPtr GetExport(string name)
        {
            return NativeLibrary.GetExport(handle, name);
        }
        public T GetExport<T>(string name)
        {
            return Marshal.GetDelegateForFunctionPointer<T>(GetExport(name));
        }
        public T GetExport<T>()
        {
            return GetExport<T>(typeof(T).Name);
        }
        public void GetExport<T>(out T func)
        {
            func = GetExport<T>();
        }
    }
}
