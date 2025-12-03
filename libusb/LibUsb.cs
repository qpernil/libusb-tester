using System;
using System.Runtime.InteropServices;

namespace libusb
{
    public interface Extra
    {
        nint GetExtra();
        int GetExtraLength();
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

    [StructLayout(LayoutKind.Sequential)]
    public struct config_descriptor : Extra
    {
        public byte bLength;

        public byte bDescriptorType;

        public ushort wTotalLength;

        public byte bNumInterfaces;

        public byte bConfigurationValue;

        public byte iConfiguration;

        public byte bmAttributes;

        public byte MaxPower;

        public nint Interfaces;

        public nint Extra;

        public int ExtraLength;

        nint Extra.GetExtra()
        {
            return Extra;
        }

        int Extra.GetExtraLength()
        {
            return ExtraLength;
        }
    };

    [StructLayout(LayoutKind.Sequential)]
    public struct libusb_interface
    {
        public nint altsetting;

        public int num_altsetting;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct interface_descriptor : Extra
    {
        public byte bLength;

        public byte bDescriptorType;

        public byte bInterfaceNumber;

        public byte bAltSetting;

        public byte bNumEndpoints;

        public byte bInterfaceClass;

        public byte bInterfaceSubClass;

        public byte bInterfaceProtocol;

        public byte iInterface;

        public nint Endpoints;

        public nint Extra;

        public int ExtraLength;

        nint Extra.GetExtra()
        {
            return Extra;
        }

        int Extra.GetExtraLength()
        {
            return ExtraLength;
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct endpoint_descriptor : Extra
    {
        public byte bLength;

        public byte bDescriptorType;

        public byte bEndpointAddress;

        public byte bmAttributes;

        public ushort wMaxPacketSize;

        public byte bInterval;

        public byte bRefresh;

        public byte bSynchAddress;

        public nint Extra;

        public int ExtraLength;

        nint Extra.GetExtra()
        {
            return Extra;
        }

        int Extra.GetExtraLength()
        {
            return ExtraLength;
        }
    };


    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_init(out nint ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_exit(nint ctx);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate nint libusb_strerror(int code);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_device_list(nint ctx, out nint device_list);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_free_device_list(nint device_list, int unref_devices);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_device_descriptor(nint device, ref device_descriptor descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_active_config_descriptor(nint device, out nint descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_config_descriptor(nint device, byte index, out nint descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_config_descriptor_by_value(nint device, byte value, out nint descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_free_config_descriptor(nint descriptor);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate nint libusb_ref_device(nint device);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_unref_device(nint device);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_open(nint device, out nint device_handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate void libusb_close(nint device_handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_get_configuration(nint device_handle, out int configuration);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_set_configuration(nint device_handle, int configuration);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_clear_halt(nint device_handle, byte endpoint);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_reset_device(nint device_handle);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_claim_interface(nint device_handle, int interface_number);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_release_interface(nint device_handle, int interface_number);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_set_interface_alt_setting(nint device_handle, int interface_number, int alt_setting);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_interrupt_transfer(nint device_handle, byte endpoint, byte[] data, int length, out int actual_length, uint timeout);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_bulk_transfer(nint device_handle, byte endpoint, byte[] data, int length, out int actual_length, uint timeout);

    [UnmanagedFunctionPointer(CallingConvention.Cdecl)]
    public delegate int libusb_control_transfer(nint device_handle, byte request_type, byte request, ushort value, ushort index, byte[] data, ushort length, uint timeout);

    public class LibUsb
    {
        public readonly libusb_init init;
        public readonly libusb_exit exit;
        public readonly libusb_strerror strerror;
        public readonly libusb_get_device_list get_device_list;
        public readonly libusb_free_device_list free_device_list;
        public readonly libusb_get_device_descriptor get_device_descriptor;
        public readonly libusb_get_active_config_descriptor get_active_config_descriptor;
        public readonly libusb_get_config_descriptor get_config_descriptor;
        public readonly libusb_get_config_descriptor_by_value get_config_descriptor_by_value;
        public readonly libusb_free_config_descriptor free_config_descriptor;
        public readonly libusb_ref_device ref_device;
        public readonly libusb_unref_device unref_device;
        public readonly libusb_open open;
        public readonly libusb_close close;
        public readonly libusb_get_configuration get_configuration;
        public readonly libusb_set_configuration set_configuration;
        public readonly libusb_clear_halt clear_halt;
        public readonly libusb_reset_device reset_device;
        public readonly libusb_claim_interface claim_interface;
        public readonly libusb_release_interface release_interface;
        public readonly libusb_set_interface_alt_setting set_interface_alt_setting;
        public readonly libusb_interrupt_transfer interrupt_transfer;
        public readonly libusb_bulk_transfer bulk_transfer;
        public readonly libusb_control_transfer control_transfer;
        private readonly SafeNativeLibrary libusb;

        public string StrError(int code)
        {
            return $"{Marshal.PtrToStringUTF8(strerror(code))} ({code})";
        }

        public LibUsb(string libraryPath = "libusb-1.0")
        {
            libusb = new SafeNativeLibrary(libraryPath);
            libusb.GetExport(out init);
            libusb.GetExport(out exit);
            libusb.GetExport(out strerror);
            libusb.GetExport(out get_device_list);
            libusb.GetExport(out free_device_list);
            libusb.GetExport(out get_device_descriptor);
            libusb.GetExport(out get_active_config_descriptor);
            libusb.GetExport(out get_config_descriptor);
            libusb.GetExport(out get_config_descriptor_by_value);
            libusb.GetExport(out free_config_descriptor);
            libusb.GetExport(out ref_device);
            libusb.GetExport(out unref_device);
            libusb.GetExport(out get_configuration);
            libusb.GetExport(out set_configuration);
            libusb.GetExport(out open);
            libusb.GetExport(out close);
            libusb.GetExport(out clear_halt);
            libusb.GetExport(out reset_device);
            libusb.GetExport(out claim_interface);
            libusb.GetExport(out release_interface);
            libusb.GetExport(out set_interface_alt_setting);
            libusb.GetExport(out interrupt_transfer);
            libusb.GetExport(out bulk_transfer);
            libusb.GetExport(out control_transfer);
        }
    }
}
