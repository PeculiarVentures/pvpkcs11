#pragma once

#include "crypt/key.h"
#include "crypt/prov_info.h"
#include "ncrypt/key.h"

namespace mscapi {

    class CryptoKey
    {
    public:
        static Scoped<CryptoKey> Create(PCERT_PUBLIC_KEY_INFO spki);

        CryptoKey();
        CryptoKey(Scoped<Handle<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>> key);
        CryptoKey(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle, DWORD dwKeySpec = AT_KEYEXCHANGE);
        CryptoKey(Scoped<crypt::ProviderInfo> info);

        BOOL IsCNG();

        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE Get();

        DWORD GetKeySpec();
        Scoped<Buffer> GetID();

        crypt::Key * GetCKey();
        ncrypt::Key * GetNKey();

    protected:
        Scoped<crypt::ProviderInfo>                     info;
        Scoped<Handle<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>> key;

    };

}