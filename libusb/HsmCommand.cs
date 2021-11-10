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
        PutOption = 0x4f,
        GetOption = 0x50,
        GetPseudoRandom = 0x51,
        GetPubKey = 0x54,
        DecryptEcdh = 0x57,
        DeleteObject = 0x58,
        AttestAsymmetric = 0x64,
        ChangeAuthKey = 0x6c,
        PutSymmetricKey = 0x6d,
        GenerateSymmetricKey = 0x6e,
        DecryptEcb = 0x6f,
        EncryptEcb = 0x70,
        DecryptCbc = 0x71,
        EncryptCbc = 0x72,
        GetClientPubKey = 0x73,
        GetChallenge = 0x74,
        ClientAuth = 0x75,
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

    public enum ObjectType : byte
    {
        Opaque = 1,
        AuthenticationKey = 2,
        AsymmetricKey = 3,
        WrapKey = 4,
        HmacKey = 5,
        SshTemplate = 6,
        OtpAeadKey = 7,
        SymmetricKey = 8
    }

    public enum Algorithm : byte
    {
        EC_P256 = 12,
        SCP_03 = 38,
        SCP_11 = 49,
        AES_128 = 50,
        AES_192 = 51,
        AES_256 = 52,
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
        ChangeAuthKey = 1ul << 0x2e,
        DecryptAesEcb = 1ul << 0x32,
        EncryptAesEcb = 1ul << 0x33,
        DecryptAesCbc = 1ul << 0x34,
        EncryptAesCbc = 1ul << 0x35
    }

    public class PutAuthKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52
        public Capability delegated_caps; // 53
        public ReadOnlyMemory<byte> key; // 61

        public HsmCommand Command => HsmCommand.PutAuthKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
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
        public Algorithm algorithm; // 52
        public ReadOnlyMemory<byte> key; // 53

        public HsmCommand Command => HsmCommand.PutAsymmetricKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
            s.Write(key.Span);
        }
    }

    public class GetAlgorithmToggleReq : IWriteable
    {
        public HsmCommand Command => HsmCommand.GetOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(4);
        }
    }

    public class PutAlgorithmToggleReq : IWriteable
    {
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.PutOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(4);
            s.Write((ushort)data.Length);
            s.Write(data.Span);
        }
    }

    public class GenerateSymmetricKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52

        public HsmCommand Command => HsmCommand.GenerateSymmetricKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
        }
    }

    public class PutSymmetricKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52
        public ReadOnlyMemory<byte> key; // 53

        public HsmCommand Command => HsmCommand.PutSymmetricKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
            s.Write(key.Span);
        }
    }

    public class EncryptEcbReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.EncryptEcb;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(data.Span);
        }
    }

    public class DecryptEcbReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.DecryptEcb;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(data.Span);
        }
    }

    public class EncryptCbcReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> iv;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.EncryptCbc;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(iv.Span);
            s.Write(data.Span);
        }
    }

    public class DecryptCbcReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> iv;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.DecryptCbc;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(iv.Span);
            s.Write(data.Span);
        }
    }

    public class ChangeAuthKeyReq : IWriteable
    {
        public ushort key_id;
        public Algorithm algorithm;
        public ReadOnlyMemory<byte> key;

        public HsmCommand Command => HsmCommand.ChangeAuthKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)algorithm);
            s.Write(key.Span);
        }
    }

    public class DeleteObjectReq : IWriteable
    {
        public ushort key_id;
        public ObjectType key_type;

        public HsmCommand Command => HsmCommand.DeleteObject;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)key_type);
        }
    }

    public class GetChallengeReq : IWriteable
    {
        public ushort key_id;

        public HsmCommand Command => HsmCommand.GetChallenge;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
        }
    }

    public class CreateSessionReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> host_chal;

        public HsmCommand Command => HsmCommand.CreateSession;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(host_chal.Span);
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
        public ReadOnlyMemory<byte> key;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(7);
            s.Write((ulong)delegated_caps);
            s.Write(key.Span);
        }
    }

    public class SetAttestKeyReq : IWriteable
    {
        public Algorithm algorithm;
        public ReadOnlyMemory<byte> key;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(4);
            s.WriteByte((byte)algorithm);
            s.Write(key.Span);
        }
    }

    public class SetAttestCertReq : IWriteable
    {
        public ReadOnlyMemory<byte> cert;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(5);
            s.Write(cert.Span);
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
        public ObjectType key_type;

        public HsmCommand Command => HsmCommand.GetObjectInfo;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)key_type);
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
