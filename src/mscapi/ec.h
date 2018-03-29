#pragma once

#include "key.h"
#include "../core/objects/ec_key.h"

namespace mscapi {

    class EcKey {
    public:
        static Scoped<CryptoKeyPair> Generate(
            CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
            Scoped<core::Template> publicTemplate,
            Scoped<core::Template> privateTemplate
        );

        static Scoped<core::Object> DeriveKey(
            CK_MECHANISM_PTR        pMechanism,
            Scoped<core::Object>    baseKey,
            Scoped<core::Template>  tmpl
        );
    };

    class EcPrivateKey : public core::EcPrivateKey, public ObjectKey {   
    public:
        EcPrivateKey(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = L"") :
            core::EcPrivateKey(),
            ObjectKey(pszProvName, dwProvType, pszScope)
        {
            Init();
        }
        EcPrivateKey(Scoped<CryptoKey> key) :
            core::EcPrivateKey(),
            ObjectKey(key)
        {
            Init();
        }

        CK_RV CopyValues
        (
            Scoped<core::Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
            CK_ULONG                ulCount     /* attributes in template */
        );

        CK_RV Destroy();

    protected:
        void Init();
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

    class EcPublicKey : public core::EcPublicKey, public ObjectKey {
    public:
        EcPublicKey(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = L"") :
            core::EcPublicKey(), 
            ObjectKey(pszProvName, dwProvType, pszScope)
        {}

        EcPublicKey(Scoped<CryptoKey> key) :
            core::EcPublicKey(),
            ObjectKey(key)
        {}

        CK_RV CreateValues
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV CopyValues(
            Scoped<core::Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
            CK_ULONG                ulCount     /* attributes in template */
        );

        CK_RV Destroy();

        void FillKeyStruct();
    protected:

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

}