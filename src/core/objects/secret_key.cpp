#include "secret_key.h"

using namespace core;

SecretKey::SecretKey() :
    Key()
{

    ItemByType(CKA_CLASS)->To<AttributeNumber>()->Set(CKO_SECRET_KEY);

    Add(AttributeBool::New(CKA_SENSITIVE, false, PVF_8 | PVF_11));
    Add(AttributeBool::New(CKA_ENCRYPT, false, PVF_8));
    Add(AttributeBool::New(CKA_DECRYPT, false, PVF_8));
    Add(AttributeBool::New(CKA_SIGN, false, PVF_8));
    Add(AttributeBool::New(CKA_VERIFY, false, PVF_8));
    Add(AttributeBool::New(CKA_WRAP, false, PVF_8));
    Add(AttributeBool::New(CKA_UNWRAP, false, PVF_8));
    Add(AttributeBool::New(CKA_EXTRACTABLE, false, PVF_8 | PVF_12));
    Add(AttributeBool::New(CKA_ALWAYS_SENSITIVE, false, PVF_2 | PVF_4 | PVF_6));
    Add(AttributeBool::New(CKA_NEVER_EXTRACTABLE, false, PVF_2 | PVF_4 | PVF_6));
    Add(AttributeBytes::New(CKA_CHECK_VALUE, NULL, 0, 0));
    Add(AttributeBool::New(CKA_WRAP_WITH_TRUSTED, false, PVF_11));
    Add(AttributeBool::New(CKA_TRUSTED, false, PVF_10));
    Add(AttributeBytes::New(CKA_WRAP_TEMPLATE, NULL, 0, 0));
    Add(AttributeBytes::New(CKA_UNWRAP_TEMPLATE, NULL, 0, 0));
}