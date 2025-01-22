using System;
using System.Collections.Generic;
using Net.Pkcs11Interop.Common;
using Net.Pkcs11Interop.HighLevelAPI;

namespace libusb_tester
{
    public class Pkcs11RsaDecryptor : IDisposable
    {
        readonly IPkcs11Library lib;
        readonly ISession session;
        readonly IObjectHandle key;

        public Pkcs11RsaDecryptor(string password, ulong bits)
        {
            var factories = new Pkcs11InteropFactories();
            lib = factories.Pkcs11LibraryFactory.LoadPkcs11Library(factories, "/usr/local/lib/libykcs11.dylib", AppType.SingleThreaded);
            foreach (var slot in lib.GetSlotList(SlotsType.WithTokenPresent))
            {
                session = slot.OpenSession(SessionType.ReadWrite);
                session.Login(CKU.CKU_USER, password);

                var keys = session.FindAllObjects(new List<IObjectAttribute> { factories.ObjectAttributeFactory.Create(CKA.CKA_CLASS, CKO.CKO_PRIVATE_KEY),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_KEY_TYPE, CKK.CKK_RSA),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_MODULUS_BITS, bits),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_EXTRACTABLE, false),
                                                                                factories.ObjectAttributeFactory.Create(CKA.CKA_TOKEN, true)});
                if (keys.Count > 0)
                {
                    key = keys[0];
                    break;
                }
            }
        }

        public void Dispose()
        {
            session?.Dispose();
            lib.Dispose();
        }

        public bool HasPubKey => key != null;

        public byte[] GetModulus()
        {
            return session?.GetAttributeValue(key, new List<CKA> { CKA.CKA_MODULUS })[0].GetValueAsByteArray();
        }
    }
}
