#include "rsa_public_key.h"

using namespace core;

RsaPublicKey::RsaPublicKey() :
    PublicKey()
{
    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_RSA);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_RSA_PKCS_KEY_PAIR_GEN);

        Add(AttributeBytes::New(CKA_MODULUS, NULL, 0, PVF_1 | PVF_4));
        Add(AttributeNumber::New(CKA_MODULUS_BITS, 0, PVF_2 | PVF_3));
        Add(AttributeBytes::New(CKA_PUBLIC_EXPONENT, NULL, 0, PVF_1));
    }
    CATCH_EXCEPTION
}