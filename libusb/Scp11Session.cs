using System;
using System.IO;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Security;

namespace libusb
{
    public class Scp11Session : Scp03CryptoSession
    {
        public Scp11Session(Scp11Context context, Session session, ushort key_id)
        {
            var pair = context.generator.GenerateKeyPair();

            var epk_oce = (ECPublicKeyParameters)pair.Public;

            var esk_oce = AgreementUtilities.GetBasicAgreement("ECDH");
            esk_oce.Init(pair.Private);

            var req = new CreateSessionReq
            {
                key_id = key_id,
                host_chal = epk_oce.Q.GetEncoded()
            };
            var resp = session.SendCmd(req);

            session_id = resp[0];
            var epk_sd = context.DecodePoint(resp.Slice(1, 65));
            var receipt = resp.Slice(1 + 65, 16);

            var shsee = esk_oce.CalculateAgreement(epk_sd).ToByteArrayFixed();
            var shs_oce = context.CalculateShs(shsee, 4 * 16).ToArray();

            var receipt_key = new KeyParameter(shs_oce, 0, 16);
            key_enc = new KeyParameter(shs_oce, 16, 16);
            var key_mac = new KeyParameter(shs_oce, 32, 16);
            var key_rmac = new KeyParameter(shs_oce, 48, 16);

            cmac.Init(receipt_key);
            cmac.BlockUpdate(epk_sd.Q.GetEncoded());
            cmac.BlockUpdate(epk_oce.Q.GetEncoded());
            var receipt_oce = new byte[16];
            cmac.DoFinal(receipt_oce, 0);

            if (!receipt.SequenceEqual(receipt_oce))
            {
                throw new IOException("The card receipt was invalid");
            }

            this.session = new Scp03CMacSession(cmac, session, key_mac, key_rmac, receipt_oce);
        }

        public Scp11Session(Session session, ushort key_id, Session auth_session, ushort auth_key_id)
        {
            var epk_oce = auth_session.SendCmd(new GetChallengeReq { key_id = auth_key_id }).ToArray();
            if (epk_oce[0] != 49)
                throw new IOException($"Unknown ephemeral key algorithm: {epk_oce[0]}");
            epk_oce[0] = 0x04;

            var req = new CreateSessionReq
            {
                key_id = key_id,
                host_chal = epk_oce
            };
            var resp = session.SendCmd(req);

            session_id = resp[0];
            var epk_sd = resp.Slice(1, 65).ToArray();
            var receipt = resp.Slice(1 + 65, 16).ToArray();

            var client_auth = new ClientAuthReq
            {
                key_id = auth_key_id,
                host_chal = epk_oce,
                card_chal = epk_sd,
                card_crypto = receipt
            };
            var auth_resp = auth_session.SendCmd(client_auth).ToArray();

            key_enc = new KeyParameter(auth_resp, 0, 16);
            var key_mac = new KeyParameter(auth_resp, 16, 16);
            var key_rmac = new KeyParameter(auth_resp, 32, 16);

            this.session = new Scp03CMacSession(cmac, session, key_mac, key_rmac, receipt);
        }
    }
}
