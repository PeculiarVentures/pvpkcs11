#pragma once

#include "../stdafx.h"
#include "helper.h"
#include "sec.h"

namespace osx {
    
    class Key {
    public:
        Key() : value(NULL) {}
        
        Scoped<SecKey> Get();
    protected:
        Scoped<SecKey> value;
    };
    
}
