#pragma once

#include "../stdafx.h"
#include "../core/template.h"
#include "../core/objects/rsa_private_key.h"
#include "../core/objects/rsa_public_key.h"
#include "key.h"

namespace mscapi
{

    class RsaKey
    {
    public:
        static Scoped<CryptoKeyPair> Generate(
            CK_MECHANISM_PTR pMechanism, /* key-gen mechanism */
            Scoped<core::Template> publicTemplate,
            Scoped<core::Template> privateTemplate);
    };

    class RsaPrivateKey : public core::RsaPrivateKey, public ObjectKey
    {
    public:
        RsaPrivateKey(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = L"")
            : core::RsaPrivateKey(),
              ObjectKey(pszProvName, dwProvType, pszScope)
        {
            Init();
        };
        RsaPrivateKey(Scoped<CryptoKey> key)
            : core::RsaPrivateKey(),
              ObjectKey(key)
        {
            Init();
        }

        CK_RV CopyValues(
            Scoped<core::Object> object, /* the object which must be copied */
            CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
            CK_ULONG ulCount             /* attributes in template */
        );

        CK_RV Destroy();

    protected:
        void Init();
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();
        void FillPinData();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr);
    };

    class RsaPublicKey : public core::RsaPublicKey, public ObjectKey
    {
    public:
        RsaPublicKey(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = L"") : core::RsaPublicKey(),
                                                                                                                  ObjectKey(pszProvName, dwProvType, pszScope){};

        RsaPublicKey(Scoped<CryptoKey> key) : core::RsaPublicKey(),
                                              ObjectKey(key){};

        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
            CK_ULONG ulCount            /* attributes in template */
        );

        CK_RV CopyValues(
            Scoped<core::Object> object, /* the object which must be copied */
            CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
            CK_ULONG ulCount             /* attributes in template */
        );

        CK_RV Destroy();

        void Import(Scoped<Buffer> data);

        void FillKeyStruct();

    protected:
        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr);
    };

}