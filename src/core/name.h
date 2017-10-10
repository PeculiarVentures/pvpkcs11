#pragma once

#include "../stdafx.h"

namespace core {

    class Name {
    public:
        static const char* getResultValue(CK_RV value);
        static const char* getAttribute(CK_ATTRIBUTE_TYPE value);
        static const char* getMechanism(CK_MECHANISM_TYPE value);
    };

}
