#include "private_key.h"

using namespace core;

PrivateKey::PrivateKey() :
    Key()
{
    ItemByType(CKA_CLASS)->To<AttributeNumber>()->Set(CKO_PRIVATE_KEY);

    Add(AttributeBytes::New(CKA_SUBJECT, NULL, 0, PVF_8));
    Add(AttributeBool::New(CKA_SENSITIVE, CK_FALSE, PVF_8 | PVF_11));
    Add(AttributeBool::New(CKA_DECRYPT, CK_FALSE, PVF_8));
    Add(AttributeBool::New(CKA_SIGN, CK_FALSE, PVF_8));
    Add(AttributeBool::New(CKA_SIGN_RECOVER, CK_FALSE, PVF_8));
    Add(AttributeBool::New(CKA_UNWRAP, CK_FALSE, PVF_8));
    Add(AttributeBool::New(CKA_EXTRACTABLE, CK_FALSE, PVF_8 | PVF_12));
    Add(AttributeBool::New(CKA_ALWAYS_SENSITIVE, CK_FALSE, PVF_2 | PVF_4 | PVF_6));
    Add(AttributeBool::New(CKA_NEVER_EXTRACTABLE, CK_FALSE, PVF_2 | PVF_4 | PVF_6));
    Add(AttributeBool::New(CKA_WRAP_WITH_TRUSTED, CK_FALSE, PVF_11));
    Add(AttributeBytes::New(CKA_UNWRAP_TEMPLATE, NULL, 0, 0));
    Add(AttributeBool::New(CKA_ALWAYS_AUTHENTICATE, CK_FALSE, 0));

}
