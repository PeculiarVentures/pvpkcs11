#pragma once

#include "../stdafx.h"
#include "helper.h"

#include <Security/Security.h>

namespace osx {
    
    class Key {
    public:
        Key() : value(NULL) {}
        
        SecKeyRef Get();
    protected:
        CFRef<SecKeyRef> value;
    };
    
}
