#include "crypt.h"

crypt::ProviderInfo::ProviderInfo()
{
    info = NULL;
}

crypt::ProviderInfo::ProviderInfo(Scoped<Buffer> buffer) :
    ProviderInfo()
{
    Assign(buffer);
}

void crypt::ProviderInfo::Assign(Scoped<Buffer> buffer)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!buffer.get()) {
            THROW_EXCEPTION("Parameter buffer is empty");
        }

        this->buffer = buffer;
        info = reinterpret_cast<CRYPT_KEY_PROV_INFO*>(buffer->data());

    }
    CATCH_EXCEPTION
}

CRYPT_KEY_PROV_INFO * crypt::ProviderInfo::Get()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!info) {
            THROW_EXCEPTION("CRYPT_KEY_PROV_INFO param is empty. Use Assign first");
        }

        return info;
    }
    CATCH_EXCEPTION
}