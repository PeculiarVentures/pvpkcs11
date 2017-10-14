#include "aes_key.h"

using namespace core;

AesKey::AesKey() :
    SecretKey()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_AES);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_AES_KEY_GEN);

        Add(AttributeBytes::New(CKA_VALUE, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7));
        Add(AttributeNumber::New(CKA_VALUE_LEN, 0, PVF_2 | PVF_3 | PVF_6));
    }
    CATCH_EXCEPTION
}
