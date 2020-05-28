using System;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

namespace libusb
{
    public class SafeNativeLibrary : SafeHandleZeroOrMinusOneIsInvalid
    {
        public SafeNativeLibrary(string libraryPath) : base(true)
        {
            handle = NativeLibrary.Load(libraryPath);
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
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct device_descriptor
    {
        /** Size of this descriptor (in bytes) */
        public byte bLength;

        /** Descriptor type. Will have value
         * \ref libusb_descriptor_type::LIBUSB_DT_DEVICE LIBUSB_DT_DEVICE in this
         * context. */
        public byte bDescriptorType;

        /** USB specification release number in binary-coded decimal. A value of
         * 0x0200 indicates USB 2.0, 0x0110 indicates USB 1.1, etc. */
        public ushort bcdUSB;

        /** USB-IF class code for the device. See \ref libusb_class_code. */
        public byte bDeviceClass;

        /** USB-IF subclass code for the device, qualified by the bDeviceClass
         * value */
        public byte bDeviceSubClass;

        /** USB-IF protocol code for the device, qualified by the bDeviceClass and
         * bDeviceSubClass values */
        public byte bDeviceProtocol;

        /** Maximum packet size for endpoint 0 */
        public byte bMaxPacketSize0;

        /** USB-IF vendor ID */
        public ushort idVendor;

        /** USB-IF product ID */
        public ushort idProduct;

        /** Device release number in binary-coded decimal */
        public ushort bcdDevice;

        /** Index of string descriptor describing manufacturer */
        public byte iManufacturer;

        /** Index of string descriptor describing product */
        public byte iProduct;

        /** Index of string descriptor containing device serial number */
        public byte iSerialNumber;

        /** Number of possible configurations */
        public byte bNumConfigurations;
    };

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_init(out IntPtr ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_exit(IntPtr ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_device_list(IntPtr ctx, out IntPtr device_list);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_free_device_list(IntPtr device_list, int unref_devices);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_device_descriptor(IntPtr device, ref device_descriptor descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr libusb_ref_device(IntPtr device);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate IntPtr libusb_unref_device(IntPtr device);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_open(IntPtr device, out IntPtr device_handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_close(IntPtr device_handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_claim_interface(IntPtr device_handle, int interface_number);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_release_interface(IntPtr device_handle, int interface_number);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_interrupt_transfer(IntPtr device_handle, byte endpoint, byte[] data, int length, out int actual_length, uint timeout);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_bulk_transfer(IntPtr device_handle, byte endpoint, byte[] data, int length, out int actual_length, uint timeout);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_control_transfer(IntPtr device_handle, byte request_type, byte request, ushort value, ushort index, byte[] data, ushort length, uint timeout);

    public class LibUsb
    {
        public libusb_init init;
        public libusb_exit exit;
        public libusb_get_device_list get_device_list;
        public libusb_free_device_list free_device_list;
        public libusb_get_device_descriptor get_device_descriptor;
        public libusb_ref_device ref_device;
        public libusb_unref_device unref_device;
        public libusb_open open;
        public libusb_close close;
        public libusb_claim_interface claim_interface;
        public libusb_release_interface release_interface;
        public libusb_interrupt_transfer interrupt_transfer;
        public libusb_bulk_transfer bulk_transfer;
        public libusb_control_transfer control_transfer;

        private SafeNativeLibrary libusb;

        public LibUsb(string libraryPath = "/usr/local/lib/libusb-1.0.dylib")
        {
            libusb = new SafeNativeLibrary(libraryPath);
            init = libusb.GetExport<libusb_init>();
            exit = libusb.GetExport<libusb_exit>();
            get_device_list = libusb.GetExport<libusb_get_device_list>();
            free_device_list = libusb.GetExport<libusb_free_device_list>();
            get_device_descriptor = libusb.GetExport<libusb_get_device_descriptor>();
            ref_device = libusb.GetExport<libusb_ref_device>();
            unref_device = libusb.GetExport<libusb_unref_device>();
            open = libusb.GetExport<libusb_open>();
            close = libusb.GetExport<libusb_close>();
            claim_interface = libusb.GetExport<libusb_claim_interface>();
            release_interface = libusb.GetExport<libusb_release_interface>();
            interrupt_transfer = libusb.GetExport<libusb_interrupt_transfer>();
            bulk_transfer = libusb.GetExport<libusb_bulk_transfer>();
            control_transfer = libusb.GetExport<libusb_control_transfer>();
        }
    }
}
