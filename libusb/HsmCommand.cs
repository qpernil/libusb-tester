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
        PutOpaque = 0x42,
        GetOpaque = 0x43,
        PutAuthKey = 0x44,
        PutAsymmetricKey = 0x45,
        GenerateAsymmetricKey = 0x46,
        SignPkcs1 = 0x47,
        ListObjects = 0x48,
        DecryptPkcs1 = 0x49,
        ExportWrapped = 0x4a,
        ImportWrapped = 0x4b,
        PutWrapKey = 0x4c,
        GetLogs = 0x4d,
        GetObjectInfo = 0x4e,
        PutOption = 0x4f,
        GetOption = 0x50,
        GetPseudoRandom = 0x51,
        GetPubKey = 0x54,
        SignPss = 0x55,
        SignEcdsa = 0x56,
        DecryptEcdh = 0x57,
        DeleteObject = 0x58,
        DecryptOaep = 0x59,
        AttestAsymmetric = 0x64,
        SetLogIndex = 0x67,
        ChangeAuthKey = 0x6c,
        PutSymmetricKey = 0x6d,
        GenerateSymmetricKey = 0x6e,
        SignEddsa = 0x6a,
        DecryptEcb = 0x6f,
        EncryptEcb = 0x70,
        DecryptCbc = 0x71,
        EncryptCbc = 0x72,
        PutPublicWrapKey = 0x73,
        GetRsaWrapped = 0x74,
        PutRsaWrapped = 0x75,
        ExportRsaWrapped = 0x76,
        ImportRsaWrapped = 0x77,
        UnwrapKwp = 0x78,
        WrapKwp = 0x79,
        // Fake command codes for now
        GetClientPubKey = 0x32,
        GetChallenge = 0x33,
        ClientAuth = 0x34,
        Error = 0x35
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
        None = 0,
        Opaque = 1,
        AuthenticationKey = 2,
        AsymmetricKey = 3,
        WrapKey = 4,
        HmacKey = 5,
        SshTemplate = 6,
        OtpAeadKey = 7,
        SymmetricKey = 8,
        PublicWrapKey = 9
    }

    public enum Algorithm : byte
    {
        RSA_2048 = 9,
        RSA_3072 = 10,
        RSA_4096 = 11,
        EC_P256 = 12,
        EC_P384 = 13,
        EC_P521 = 14,
        RSA_OAEP_SHA1 = 25,
        RSA_OAEP_SHA256 = 26,
        RSA_OAEP_SHA384 = 27,
        RSA_OAEP_SHA512 = 28,
        AES128_CCM_WRAP = 29,
        OPAQUE_DATA = 30,
        OPAQUE_X509_CERT = 31,
        MGF1_SHA1 = 32,
        MGF1_SHA256 = 33,
        MGF1_SHA384 = 34,
        MGF1_SHA512 = 35,
        AES128_YUBICO_AUTHENTICATION = 38,
        AES192_CCM_WRAP = 41,
        AES256_CCM_WRAP = 42,
        ED25519 = 46,
        EC_P224 = 47,
        EC_P256_YUBICO_AUTHENTICATION = 49,
        AES_128 = 50,
        AES_192 = 51,
        AES_256 = 52,
    }

    [Flags]
    public enum Capability : ulong
    {
        PutAuthKey = 1ul << 0x02,
        PutAsymmetricKey = 1ul << 0x03,
        GenerateAsymmetricKey = 1ul << 0x04,
        SignPkcs = 1ul << 0x05,
        SignPss = 1ul << 0x06,
        SignEcdsa = 1ul << 0x07,
        SignEddsa = 1ul << 0x08,
        DecryptPkcs1 = 1ul << 0x09,
        DecryptOaep = 1ul << 0x0a,
        DecryptEcdh = 1ul << 0x0b,
        ExportWrapped = 1ul << 0x0c,
        ImportWrapped = 1ul << 0x0d,
        PutWrapKey = 1ul << 0x0e,
        ExportUnderWrap = 1ul << 0x10,
        GetRandom = 1ul << 0x13,
        Reset = 1ul << 0x1c,
        Attest = 1ul << 0x22,
        DeleteAuthKey = 1ul << 0x28,
        DeleteAsymmetricKey = 1ul << 0x29,
        ChangeAuthKey = 1ul << 0x2e,
        PutSymmetricKey = 1ul << 0x2f,
        GenerateSymmetricKey = 1ul << 0x30,
        DeleteSymmetricKey = 1ul << 0x31,
        DecryptEcb = 1ul << 0x32,
        EncryptEcb = 1ul << 0x33,
        DecryptCbc = 1ul << 0x34,
        EncryptCbc = 1ul << 0x35,
        PutPublicWrapKey = 1ul << 0x36,
        DeletePublicWrapKey = 1ul << 0x37,
        DecryptKwp = 1ul << 0x38,
        EncryptKwp = 1ul << 0x39,
        ClientAuth = 1ul << 0x3f,
        All = ulong.MaxValue
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

    public class PutWrapKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52
        public Capability delegated_caps; // 53
        public ReadOnlyMemory<byte> key; // 61

        public HsmCommand Command => HsmCommand.PutWrapKey;

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

    public class PutPublicWrapKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52
        public Capability delegated_caps; // 53
        public ReadOnlyMemory<byte> key; // 61

        public HsmCommand Command => HsmCommand.PutPublicWrapKey;

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

    public class ExportWrappedReq : IWriteable
    {
        public ushort key_id;
        public ObjectType target_type;
        public ushort target_key;
        public byte format;

        public HsmCommand Command => HsmCommand.ExportWrapped;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)target_type);
            s.Write(target_key);
            if (format != 0)
            {
                s.WriteByte(format);
            }
        }
    }

    public class ImportWrappedReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> wrapped_key;

        public HsmCommand Command => HsmCommand.ImportWrapped;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(wrapped_key.Span);
        }
    }

    public class ExportRsaWrappedReq : IWriteable
    {
        public ushort key_id;
        public ObjectType target_type;
        public ushort target_key;
        public Algorithm aes_algorithm;
        public Algorithm hash_algorithm;
        public Algorithm mgf_algorithm;
        public ReadOnlyMemory<byte> digest;
        
        public HsmCommand Command => HsmCommand.ExportRsaWrapped;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)target_type);
            s.Write(target_key);
            s.WriteByte((byte)aes_algorithm);
            s.WriteByte((byte)hash_algorithm);
            s.WriteByte((byte)mgf_algorithm);
            s.Write(digest.Span);
        }
    }

    public class ImportRsaWrappedReq : IWriteable
    {
        public ushort key_id;
        public Algorithm hash_algorithm;
        public Algorithm mgf_algorithm;
        public ReadOnlyMemory<byte> wrapped_key;
        public ReadOnlyMemory<byte> digest;

        public HsmCommand Command => HsmCommand.ImportRsaWrapped;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)hash_algorithm);
            s.WriteByte((byte)mgf_algorithm);
            s.Write(wrapped_key.Span);
            s.Write(digest.Span);
        }
    }

    public class GetRsaWrappedReq : IWriteable
    {
        public ushort key_id;
        public ObjectType target_type;
        public ushort target_key;
        public Algorithm aes_algorithm;
        public Algorithm hash_algorithm;
        public Algorithm mgf_algorithm;
        public ReadOnlyMemory<byte> digest;

        public HsmCommand Command => HsmCommand.GetRsaWrapped;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)target_type);
            s.Write(target_key);
            s.WriteByte((byte)aes_algorithm);
            s.WriteByte((byte)hash_algorithm);
            s.WriteByte((byte)mgf_algorithm);
            s.Write(digest.Span);
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

    public class GenerateAsymmetricKeyReq : IWriteable
    {
        public ushort key_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52

        public HsmCommand Command => HsmCommand.GenerateAsymmetricKey;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
        }
    }

    public class GetForcedAuditReq : IWriteable
    {
        public HsmCommand Command => HsmCommand.GetOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(1);
        }
    }

    public class PutForcedAuditReq : IWriteable
    {
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.PutOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(1);
            s.Write((ushort)data.Length);
            s.Write(data.Span);
        }
    }

    public class GetCommandAuditReq : IWriteable
    {
        public HsmCommand Command => HsmCommand.GetOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(3);
        }
    }

    public class PutCommandAuditReq : IWriteable
    {
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.PutOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(3);
            s.Write((ushort)data.Length);
            s.Write(data.Span);
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

    public class PutFipsModeReq : IWriteable
    {
        public byte fips;

        public HsmCommand Command => HsmCommand.PutOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(5);
            s.Write((ushort)1);
            s.WriteByte(fips);
        }
    }

    public class GetFipsModeReq : IWriteable
    {
        public HsmCommand Command => HsmCommand.GetOption;

        public void WriteTo(Stream s)
        {
            s.WriteByte(5);
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

    public class PutOpaqueReq : IWriteable
    {
        public ushort object_id; // 0
        public ReadOnlyMemory<byte> label; // 2
        public ushort domains; // 42
        public Capability capabilities; // 44
        public Algorithm algorithm; // 52
        public ReadOnlyMemory<byte> data; // 53

        public HsmCommand Command => HsmCommand.PutOpaque;

        public void WriteTo(Stream s)
        {
            s.Write(object_id);
            s.Write(label.Span);
            s.Write(domains);
            s.Write((ulong)capabilities);
            s.WriteByte((byte)algorithm);
            s.Write(data.Span);
        }
    }

    public class GetOpaqueReq : IWriteable
    {
        public ushort object_id; // 0

        public HsmCommand Command => HsmCommand.GetOpaque;

        public void WriteTo(Stream s)
        {
            s.Write(object_id);
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

    public class WrapKwpReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.WrapKwp;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(data.Span);
        }
    }

    public class UnwrapKwpReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.UnwrapKwp;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
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
            s.WriteByte(0x07);
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
            s.WriteByte(0x04);
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
            s.WriteByte(0x05);
            s.Write(cert.Span);
        }
    }

    public class SetSerialReq : IWriteable
    {
        public uint serial;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(0x01);
            s.Write(serial);
        }
    }

    public class SetDemoModeReq : IWriteable
    {
        public ushort demo;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(0x02);
            s.Write(demo);
        }
    }

    public class SetFipsDeviceReq : IWriteable
    {
        public byte fips;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(0x0a);
            s.WriteByte(fips);
        }
    }

    public class SetFuseReq : IWriteable
    {
        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(0x06);
        }
    }

    public class SetBslCodeReq : IWriteable
    {
        public ReadOnlyMemory<byte> code;

        public HsmCommand Command => HsmCommand.SetInformation;

        public void WriteTo(Stream s)
        {
            s.WriteByte(0x03);
            s.Write(code.Span);
        }
    }

    public class BslReq : IWriteable
    {
        public ReadOnlyMemory<byte> code;

        public HsmCommand Command => HsmCommand.Bsl;

        public void WriteTo(Stream s)
        {
            s.Write(code.Span);
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

    public class SignPkcs1Req : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> hash;

        public HsmCommand Command => HsmCommand.SignPkcs1;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(hash.Span);
        }
    }

    public class SignPssReq : IWriteable
    {
        public ushort key_id;
        public Algorithm mgf_algorithm;
        public ushort salt_len;
        public ReadOnlyMemory<byte> hash;

        public HsmCommand Command => HsmCommand.SignPss;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)mgf_algorithm);
            s.Write(salt_len);
            s.Write(hash.Span);
        }
    }

    public class SignEcdsaReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> hash;

        public HsmCommand Command => HsmCommand.SignEcdsa;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(hash.Span);
        }
    }

    public class SignEddsaReq : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> hash;

        public HsmCommand Command => HsmCommand.SignEddsa;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(hash.Span);
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

    public class ListObjectsReq : IWriteable
    {
        public ObjectType type;

        public HsmCommand Command => HsmCommand.ListObjects;

        public void WriteTo(Stream s)
        {
            s.WriteByte(2);
            s.WriteByte((byte)type);
        }
    }

    public class DecryptPkcs1Req : IWriteable
    {
        public ushort key_id;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.DecryptPkcs1;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.Write(data.Span);
        }
    }

    public class DecryptOaepReq : IWriteable
    {
        public ushort key_id;
        public Algorithm mgf_algorithm;
        public ReadOnlyMemory<byte> data;

        public HsmCommand Command => HsmCommand.DecryptOaep;

        public void WriteTo(Stream s)
        {
            s.Write(key_id);
            s.WriteByte((byte)mgf_algorithm);
            s.Write(data.Span);
        }
    }
}
