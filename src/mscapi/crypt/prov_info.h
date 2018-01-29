#pragma once

#include "../../stdafx.h"

namespace crypt {

    class ProviderInfo
    {
    public:
        ProviderInfo(Scoped<Buffer> info);
        ProviderInfo(
            LPCWSTR     pwszContainerName,
            LPCWSTR     pwszProvName,
            DWORD       dwProvType,
            DWORD       dwFlags,
            DWORD       dwKeySpec
        );
        ~ProviderInfo();

        bool IsAccessible();

        CRYPT_KEY_PROV_INFO* Get();

        Scoped<Buffer> GetSmartCardGUID();
        Scoped<std::string> GetSmartCardReader();
    protected:
        CRYPT_KEY_PROV_INFO * info;
        Scoped<Buffer>  buffer;
        std::wstring    pwszContainerName;
        std::wstring    pwszProvName;

        Scoped<Buffer> GetBytes(DWORD dwParam);
    };

}