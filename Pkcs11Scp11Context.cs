using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;
using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X9;
using Org.BouncyCastle.Crypto.Parameters;

namespace libusb
{
    public class Pkcs11Scp11Context : Scp11Context
    {
        public Pkcs11Scp11Context(Session session) : base(session)
        {
            var factories = new Pkcs11InteropFactories();
            using (var lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, "/usr/local/lib/libykcs11.dylib", AppType.SingleThreaded))
            {
                foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
                {
                    using (var s = slot.OpenSession(SessionType.ReadWrite))
                    {
                        s.Login(CKU.CKU_USER, "123456");

                        var keys = s.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_EC),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, 256) });

                        if (keys.Count > 0)
                        {
                            var bytes = s.GetAttributeValue(keys[0], new List<CKA> { CKA.CKA_EC_POINT })[0].GetValueAsByteArray();
                            var octets = (Asn1OctetString)Asn1Object.FromByteArray(bytes);
                            X9ECPoint point = new X9ECPoint(domain.Curve, octets);
                            pk_oce = new ECPublicKeyParameters(point.Point, domain);

                            var mech = factories.MechanismFactory.Create(CKM.CKM_ECDH1_DERIVE,
                                factories.MechanismParamsFactory.CreateCkEcdh1DeriveParams((ulong)CKD.CKD_NULL, null, pk_sd.Q.GetEncoded()));

                            var obj = s.DeriveKey(mech, keys[0], new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_SECRET_KEY),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_GENERIC_SECRET),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, true),
                                                                                        factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, false)});

                            var v = s.GetAttributeValue(obj, new List<CKA> { CKA.CKA_VALUE });
                            shsss = v[0].GetValueAsByteArray();

                            s.DestroyObject(obj);

                            break;
                        }
                    }
                }
            }
        }
    }
}
