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

    protected:
        void FillKeyStruct();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

    class EcPublicKey : public core::EcPublicKey, public CryptoKey {
    public:
        EcPublicKey(
        ) : core::EcPublicKey(), CryptoKey()
        {}

    protected:
        void FillKeyStruct();
        
        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

}