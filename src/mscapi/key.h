#pragma once

#include "../stdafx.h"

#include "../core/objects/private_key.h"
#include "../core/objects/public_key.h"
#include "crypto_key.h"

namespace mscapi {

    class CryptoKeyPair {
    public:
        CryptoKeyPair(
            Scoped<core::PrivateKey> privateKey,
            Scoped<core::PublicKey> publicKey
        );

        Scoped<core::PrivateKey> privateKey;
        Scoped<core::PublicKey>  publicKey;
    };

    class ObjectKey {
    public:
        ObjectKey(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = NULL);
        ObjectKey(Scoped<CryptoKey> key);

        Scoped<CryptoKey> GetKey();
        void SetKey(Scoped<CryptoKey> value);
        void SetKey(Scoped<Handle<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>> value);
    protected:
        Scoped<CryptoKey> key;

        std::wstring    wstrProvName;
        std::wstring    wstrScope;
        DWORD           dwProvType;
    };

}