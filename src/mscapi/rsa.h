#pragma once

#include "../stdafx.h"
#include "../core/template.h"
#include "../core/objects/rsa_private_key.h"
#include "../core/objects/rsa_public_key.h"
#include "key.h"

namespace mscapi {

    class RsaKey {
    public:
        static Scoped<CryptoKeyPair> Generate(
            CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
            Scoped<core::Template> publicTemplate,
            Scoped<core::Template> privateTemplate
        );
    };

    class RsaPrivateKey : public core::RsaPrivateKey, public CryptoKey {
    public:
        RsaPrivateKey() :
            core::RsaPrivateKey(),
            CryptoKey()
        {};

    protected:
        void FillKeyStruct();

        CK_RV GetValue(
            CK_ATTRIBUTE_PTR attr
        );
    };

    class RsaPublicKey : public core::RsaPublicKey, public CryptoKey {
    public:
        RsaPublicKey() :
            core::RsaPublicKey(),
            CryptoKey()
        {};


    protected:
        void FillKeyStruct();

        CK_RV GetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );
    };

}