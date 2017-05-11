#pragma once

#include "../stdafx.h"

#include "../core/objects/aes_key.h"
#include "key.h"
#include "ncrypt.h"
#include "crypto.h"

namespace mscapi {

    class AesKey : public core::AesKey, public CryptoKey {
    public:
        AesKey(Scoped<bcrypt::Key> key) :
            core::AesKey(),
            CryptoKey(key)
        {}

        static Scoped<core::SecretKey> Generate(
            CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
            Scoped<core::Template> tmpl
        );
    };

    class CryptoAesCBCEncrypt : public CryptoEncrypt {
    public:
        CryptoAesCBCEncrypt(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR        pMechanism,
            Scoped<core::Object>    hKey
        );

        CK_RV Update
        (
            CK_BYTE_PTR       pPart,
            CK_ULONG          ulPartLen,
            CK_BYTE_PTR       pEncryptedPart,
            CK_ULONG_PTR      pulEncryptedPartLen
        );

        CK_RV Final
        (
            CK_BYTE_PTR       pLastEncryptedPart,
            CK_ULONG_PTR      pulLastEncryptedPartLen
        );
    
    protected:
        Scoped<bcrypt::Algorithm>   provider;
        AesKey*                     key;
        Scoped<std::string>         iv;
    };

}