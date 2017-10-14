#include "public_key.h"

using namespace core;

PublicKey::PublicKey() :
    Key()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        ItemByType(CKA_CLASS)->To<AttributeNumber>()->Set(CKO_PUBLIC_KEY);

        Add(AttributeBytes::New(CKA_SUBJECT, NULL, 0, PVF_8));
        Add(AttributeBool::New(CKA_ENCRYPT, false, PVF_8));
        Add(AttributeBool::New(CKA_VERIFY, false, PVF_8));
        Add(AttributeBool::New(CKA_VERIFY_RECOVER, false, PVF_8));
        Add(AttributeBool::New(CKA_WRAP, false, PVF_8));
        Add(AttributeBool::New(CKA_TRUSTED, false, PVF_10));
        Add(AttributeBytes::New(CKA_WRAP_TEMPLATE, NULL, 0, 0));
    }
    CATCH_EXCEPTION
}
