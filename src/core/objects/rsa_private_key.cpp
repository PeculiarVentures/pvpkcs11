#include "rsa_private_key.h"

using namespace core;

RsaPrivateKey::RsaPrivateKey() :
    PrivateKey()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_RSA);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_RSA_PKCS_KEY_PAIR_GEN);

        Add(AttributeBytes::New(CKA_MODULUS, NULL, 0, PVF_1 | PVF_4 | PVF_6));
        Add(AttributeBytes::New(CKA_PUBLIC_EXPONENT, NULL, 0, PVF_1 | PVF_4 | PVF_6)); // PVF_1 - no in spec
        Add(AttributeBytes::New(CKA_PRIVATE_EXPONENT, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7));
        Add(AttributeBytes::New(CKA_PRIME_1, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7)); // PVF_1 - no in spec
        Add(AttributeBytes::New(CKA_PRIME_2, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7)); // PVF_1 - no in spec
        Add(AttributeBytes::New(CKA_EXPONENT_1, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7)); // PVF_1 - no in spec
        Add(AttributeBytes::New(CKA_EXPONENT_2, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7)); // PVF_1 - no in spec
        Add(AttributeBytes::New(CKA_COEFFICIENT, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7)); // PVF_1 - no in spec
    }
    CATCH_EXCEPTION
}
