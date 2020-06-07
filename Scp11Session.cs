﻿using System;
using System.Buffers.Binary;
using System.IO;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Macs;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    public class Scp11Session : Scp03CryptoSession
    {
        private static Span<byte> X963Kdf(IDigest digest, ReadOnlySpan<byte> shsee, ReadOnlySpan<byte> shsss, int length)
        {
            var size = digest.GetDigestSize();
            var cnt = 0U;
            var ms = new MemoryStream();
            ms.Write(shsee);
            ms.Write(shsss);
            ms.Write(cnt);
            var buf = ms.AsSpan();
            var cspan = buf.Slice(buf.Length - 4);
            var ret = new byte[size * ((length + size - 1) / size)];
            for (var offs = 0; offs < length; offs += size)
            {
                BinaryPrimitives.WriteUInt32BigEndian(cspan, ++cnt);
                digest.Reset();
                digest.BlockUpdate(buf);
                digest.DoFinal(ret, offs);
            }
            return ret.AsSpan(0, length);
        }

        public Scp11Session(Scp11Context context, Session session, ushort key_id)
        {
            var pair = context.generator.GenerateKeyPair();

            var pubkey = (ECPublicKeyParameters)pair.Public;
            var epk_oce = pubkey.Q.GetEncoded().AsMemory(1);

            if (epk_oce.Length != 64)
            {
                throw new IOException($"The epk_oce length was invalid");
            }

            var esk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            esk_oce.Init(pair.Private);

            var create_req = new CreateSessionReq
            {
                key_id = key_id,
                buf = epk_oce
            };

            var create_resp = session.SendCmd(create_req);

            session_id = create_resp[0];
            var epk_sd = create_resp.Slice(1, 64);
            var receipt = create_resp.Slice(1 + 64);

            if (epk_sd.Length != 64)
            {
                throw new IOException($"The epk_sd length was invalid");
            }

            var shsee = esk_oce.CalculateAgreement(context.DecodePoint(epk_sd)).ToByteArrayUnsigned();

            if (shsee.Length != 32)
            {
                throw new IOException($"The shsee length was invalid");
            }

            var shs_oce = X963Kdf(new Sha256Digest(), shsee, context.shsss.Span, 4 * 16).ToArray();

            var receipt_key = new KeyParameter(shs_oce, 0, 16);
            key_enc = new KeyParameter(shs_oce, 16, 16);
            var key_mac = new KeyParameter(shs_oce, 32, 16);
            var key_rmac = new KeyParameter(shs_oce, 48, 16);

            var cmac = new CMac(new AesEngine());
            cmac.Init(receipt_key);
            cmac.BlockUpdate(epk_sd);
            cmac.BlockUpdate(epk_oce.Span);
            var receipt_oce = new byte[16];
            cmac.DoFinal(receipt_oce, 0);

            if (!receipt.SequenceEqual(receipt_oce))
            {
                throw new IOException($"The card receipt was invalid");
            }

            this.session = new Scp03CMacSession(session, key_mac, key_rmac, receipt_oce);
        }
    }
}
