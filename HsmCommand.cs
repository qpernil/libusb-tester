using System;
using System.IO;

namespace libusb
{
    public enum HsmCommand : byte
    {
        Echo = 0x01,
        CreateSession = 0x03,
        AuthenticateSession = 0x04,
        SessionCommand = 0x05,
        DeviceInfo = 0x06,
        Bsl = 0x07,
        Reset = 0x08,
        SetInformation = 0x09,
        CloseSession = 0x40,
        PutAuthKey = 0x44,
        ListObjects = 0x48,
        GetObjectInfo = 0x4e,
        GetPseudoRandom = 0x51,
        DeleteObject = 0x58,
        GetScp11PubKey = 0x6d,
        Error = 0x7f
    }

    public enum HsmError : byte
    {
        OK = 0x00,
        INVALID_COMMAND = 0x01,
        INVALID_DATA = 0x02,
        INVALID_SESSION = 0x03,
        AUTHENTICATION_FAILED = 0x04,
        SESSIONS_FULL = 0x05,
        SESSION_FAILED = 0x06,
        STORAGE_FAILED = 0x07,
        WRONG_LENGTH = 0x08,
        INSUFFICIENT_PERMISSIONS = 0x09,
        LOG_FULL = 0x0A,
        OBJECT_NOT_FOUND = 0x0B,
        INVALID_ID = 0x0C,
        SSH_CA_CONSTRAINT_VIOLATION = 0x0E,
        INVALID_OTP = 0x0F,
        DEMO_MODE = 0x10,
        OBJECT_EXISTS = 0x11,
        COMMAND_UNEXECUTED = 0xFF
    }

    class PutAuthKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public Memory<byte> label; // 2
        public ushort domains; // 42
        public uint capabilities2; // 44
        public uint capabilities; // 48
        public byte algorithm; // 52
        public uint delegated_caps2; // 53
        public uint delegated_caps; // 57
        public Memory<byte> key; // 61

        public HsmCommand Command => HsmCommand.PutAuthKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write(capabilities2);
            s.Write(capabilities);
            s.WriteByte(algorithm);
            s.Write(delegated_caps2);
            s.Write(delegated_caps);
            s.Write(key.Span);
        }
    }

    class DeleteObjectReq : IWriteable
    {
        public ushort key_id;
        public byte key_type;

        public HsmCommand Command => HsmCommand.DeleteObject;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte(key_type);
        }
    }

    class CreateSessionReq : IWriteable
    {
        public ushort key_id;
        public Memory<byte> buf;

        public HsmCommand Command => HsmCommand.CreateSession;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(buf.Span);
        }
    }

    class AuthenticateSessionReq : IWriteable
    {
        public byte session_id;
        public Memory<byte> host_crypto;

        public HsmCommand Command => HsmCommand.AuthenticateSession;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(host_crypto.Span);
        }
    }

    class SessionCommandReq : IWriteable
    {
        public byte session_id;
        public Memory<byte> encrypted;

        public HsmCommand Command => HsmCommand.SessionCommand;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(encrypted.Span);
        }
    }

    class GetPseudoRandomReq : IWriteable
    {
        public ushort length;

        public HsmCommand Command => HsmCommand.GetPseudoRandom;

        public void WriteTo(Stream s)
        {
            s.Write(length);
        }
    }

    class SetDefaltKeyReq : IWriteable
    {
        public uint delegated_caps2;
        public uint delegated_caps;
        public Memory<byte> buf;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(7);
            s.Write(delegated_caps2);
            s.Write(delegated_caps);
            s.Write(buf.Span);
        }
    }

    class SetSerialReq : IWriteable
    {
        public uint serial;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(1);
            s.Write(serial);
        }
    }

    class GetObjectInfoReq : IWriteable
    {
        public ushort key_id;
        public byte key_type;

        public HsmCommand Command => HsmCommand.GetObjectInfo;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte(key_type);
        }
    }
}
