#include "converter.h"
#include "excep.h"

Scoped<std::string> core::Converter::ToHex(Scoped<Buffer> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        std::string res("");
        PBYTE pValue = value->data();

        for (size_t i = 0; i < value->size(); i++) {
            CHAR buf[3] = { 0 };
            sprintf_s(buf, 3, "%02X", pValue[i]);

            res += buf;
        }

        return Scoped<std::string>(new std::string(res));
    }
    CATCH_EXCEPTION
}

Scoped<std::string> core::Converter::ToHex(Scoped<std::string> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return ToHex(Scoped<Buffer>(new Buffer(value->begin(), value->end())));
    }
    CATCH_EXCEPTION
}

Scoped<std::string> core::Converter::ToHex(const char * value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return ToHex(Scoped<std::string>(new std::string(value)));
    }
    CATCH_EXCEPTION
}