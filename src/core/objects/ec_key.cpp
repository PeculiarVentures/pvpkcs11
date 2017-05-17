#include "ec_key.h"

using namespace core;

// Private Key

EcPrivateKey::EcPrivateKey() :
    PrivateKey()
{
    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_EC);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_ECDSA_KEY_PAIR_GEN);

        Add(AttributeBytes::New(CKA_ECDSA_PARAMS, NULL, 0, PVF_1 | PVF_4 | PVF_6));
        Add(AttributeBytes::New(CKA_VALUE, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7));
    }
    CATCH_EXCEPTION
}

// Public Key

EcPublicKey::EcPublicKey() :
    PublicKey()
{
    ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_EC);
    ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_ECDSA_KEY_PAIR_GEN);

    Add(AttributeBytes::New(CKA_ECDSA_PARAMS, NULL, 0, PVF_1 | PVF_3));
    Add(AttributeBytes::New(CKA_EC_POINT, NULL, 0, PVF_1 | PVF_4));
}
