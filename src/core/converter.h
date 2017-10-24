#pragma once

#include "../stdafx.h"

namespace core {

    class Converter {
    public:
        static Scoped<std::string> ToHex(Scoped<Buffer> value);
        static Scoped<std::string> ToHex(Scoped<std::string> value);
        static Scoped<std::string> ToHex(const char * value);
    };

}