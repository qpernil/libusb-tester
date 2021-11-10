using System;
using System.Reflection;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace libusb
{
    public class SafeNativeLibrary : SafeHandleZeroOrMinusOneIsInvalid
    {
        private static bool Is(OSPlatform platform) => RuntimeInformation.IsOSPlatform(platform);
        public SafeNativeLibrary(string libraryPath) : base(true)
        {
            handle = NativeLibrary.Load(libraryPath, GetType().Assembly, DllImportSearchPath.LegacyBehavior);
        }
        public SafeNativeLibrary(string windowsPath, string osxPath, string linuxPath) : this(Is(OSPlatform.Windows) ? windowsPath : Is(OSPlatform.OSX) ? osxPath : linuxPath)
        {
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
            var name = typeof(T).Name;
            if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
            {
                switch(typeof(T).GetCustomAttribute<UnmanagedFunctionPointerAttribute>()?.CharSet)
                {
                    case CharSet.Ansi:
                        name += 'A';
                        break;

                    case CharSet.Unicode:
                    case CharSet.Auto:
                        name += 'W';
                        break;
                }
            }
            return GetExport<T>(name);
        }
        public void GetExport<T>(out T func)
        {
            func = GetExport<T>();
        }
    }
}
