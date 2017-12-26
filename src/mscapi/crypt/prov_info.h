#pragma once

#include "../../stdafx.h"

namespace crypt {

    class ProviderInfo
    {
    public:
        ProviderInfo(Scoped<Buffer> info);
        ~ProviderInfo();

        bool IsAccassible();
    
        CRYPT_KEY_PROV_INFO* Get();
    
        Scoped<Buffer> GetSmartCardGUID();
        Scoped<std::string> GetSmartCardReader();
    protected:
        CRYPT_KEY_PROV_INFO* info;
        Scoped<Buffer> buffer;

        Scoped<Buffer> GetBytes(DWORD dwParam);
    };

}