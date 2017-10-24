#pragma once

#include "../../stdafx.h"

namespace crypt {

    class ProviderInfo
    {
    public:
        ProviderInfo(Scoped<Buffer> info);
        ~ProviderInfo();
    
        CRYPT_KEY_PROV_INFO* Get();
    
    protected:
        CRYPT_KEY_PROV_INFO* info;
        Scoped<Buffer> buffer;
    };

}