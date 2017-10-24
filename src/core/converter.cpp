#include "converter.h"
#include "excep.h"

Scoped<std::string> core::Converter::ToHex(Scoped<Buffer> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        std::string res("");
        CK_BYTE_PTR pValue = value->data();

        for (size_t i = 0; i < value->size(); i++) {
            char buf[3] = { 0 };
            sprintf(buf, "%02X", pValue[i]);

            res += std::string(buf);
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
