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

    class EcPrivateKey : public core::EcPrivateKey, public CryptoKey {
    public:
        EcPrivateKey() :
            core::EcPrivateKey(),
            CryptoKey()
        {}

        CK_RV CopyValues
        (
            Scoped<core::Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
            CK_ULONG                ulCount     /* attributes in template */
        );

    protected:
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

    class EcPublicKey : public core::EcPublicKey, public CryptoKey {
    public:
        EcPublicKey(
        ) : core::EcPublicKey(), CryptoKey()
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

    protected:
        void FillKeyStruct();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

}