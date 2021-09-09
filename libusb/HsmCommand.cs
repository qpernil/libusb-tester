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
        GetDeviceInfo = 0x06,
        Bsl = 0x07,
        Reset = 0x08,
        SetInformation = 0x09,
        GetDevicePubKey = 0x0a,
        CloseSession = 0x40,
        PutAuthKey = 0x44,
        PutAsymmetricKey = 0x45,
        ListObjects = 0x48,
        GetObjectInfo = 0x4e,
        GetPseudoRandom = 0x51,
        GetPubKey = 0x54,
        DecryptEcdh = 0x57,
        DeleteObject = 0x58,
        AttestAsymmetric = 0x64,
        ChangeAuthKey = 0x6c,
        GetClientPubKey = 0x6d,
        GenerateEphemeral = 0x6e,
        ClientAuth = 0x6f,
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
        ALGO_DISABLED = 0x12,
        COMMAND_UNEXECUTED = 0xFF
    }

    [Flags]
    public enum Capability : ulong
    {
        WriteAuthKey = 1ul << 0x02,
        DecryptEcdh = 1ul << 0x0b,
        GetRandom = 1ul << 0x13,
        Reset = 1ul << 0x1c,
        Attest = 1ul << 0x22,
        DeleteAuthKey = 1ul << 0x28,
        ChangeAuthKey = 1ul << 0x2e
    }

    public class PutAuthKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public byte algorithm; // 52
        public Capability delegated_caps; // 53
        public ReadOnlyMemory<byte> key; // 61

        public HsmCommand Command => HsmCommand.PutAuthKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte(algorithm);
            s.Write((ulong)delegated_caps);
            s.Write(key.Span);
        }
    }

    public class PutAsymmetricKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public byte algorithm; // 52
        public ReadOnlyMemory<byte> key; // 53

        public HsmCommand Command => HsmCommand.PutAsymmetricKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte(algorithm);
            s.Write(key.Span);
        }
    }

    public class ChangeAuthKeyReq : IWriteable
    {
        public ushort key_id;
        public byte algorithm;
        public ReadOnlyMemory<byte> key;

        public HsmCommand Command => HsmCommand.ChangeAuthKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte(algorithm);
            s.Write(key.Span);
        }
    }

    public class DeleteObjectReq : IWriteable
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

    public class CreateSessionReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> buf;

        public HsmCommand Command => HsmCommand.CreateSession;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(buf.Span);
        }
    }

    public class AuthenticateSessionReq : IWriteable
    {
        public byte session_id;
        public ReadOnlyMemory<byte> host_crypto;

        public HsmCommand Command => HsmCommand.AuthenticateSession;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(host_crypto.Span);
        }
    }

    public class SessionCommandReq : IWriteable
    {
        public byte session_id;
        public ReadOnlyMemory<byte> encrypted;

        public HsmCommand Command => HsmCommand.SessionCommand;

        public void WriteTo(Stream s)
        {
            s.WriteByte(session_id);
            s.Write(encrypted.Span);
        }
    }

    public class GetPseudoRandomReq : IWriteable
    {
        public ushort length;

        public HsmCommand Command => HsmCommand.GetPseudoRandom;

        public void WriteTo(Stream s)
        {
            s.Write(length);
        }
    }

    public class SetDefaltKeyReq : IWriteable
    {
        public Capability delegated_caps;
        public ReadOnlyMemory<byte> buf;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(7);
            s.Write((ulong)delegated_caps);
            s.Write(buf.Span);
        }
    }

    public class SetAttestKeyReq : IWriteable
    {
        public byte algorithm;
        public ReadOnlyMemory<byte> buf;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(4);
            s.WriteByte(algorithm);
            s.Write(buf.Span);
        }
    }

    public class SetAttestCertReq : IWriteable
    {
        public ReadOnlyMemory<byte> buf;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(5);
            s.Write(buf.Span);
        }
    }

    public class SetSerialReq : IWriteable
    {
        public uint serial;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(1);
            s.Write(serial);
        }
    }

    public class SetDemoModeReq : IWriteable
    {
        public ushort demo;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(2);
            s.Write(demo);
        }
    }

    public class GetObjectInfoReq : IWriteable
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

    public class GetPubKeyReq : IWriteable
    {
        public ushort key_id;

        public HsmCommand Command => HsmCommand.GetPubKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
        }
    }

    public class AttestAsymmetricReq : IWriteable
    {
        public ushort key_id;
        public ushort attest_id;

        public HsmCommand Command => HsmCommand.AttestAsymmetric;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(attest_id);
        }
    }

    public class ClientAuthReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> host_chal;
        public ReadOnlyMemory<byte> card_chal;
        public ReadOnlyMemory<byte> card_crypto;

        public HsmCommand Command => HsmCommand.ClientAuth;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(host_chal.Span);
            s.Write(card_chal.Span);
            s.Write(card_crypto.Span);
        }
    }
}
