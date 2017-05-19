#include "certificate.h"

using namespace core;

Certificate::Certificate():
    Storage()
{
    try {
        ItemByType(CKA_CLASS)->To<AttributeNumber>()->Set(CKO_CERTIFICATE);

        Add(AttributeNumber::New(CKA_CERTIFICATE_TYPE, 0, PVF_1));
        Add(AttributeBool::New(CKA_TRUSTED, 0, PVF_10));
        Add(AttributeNumber::New(CKA_CERTIFICATE_CATEGORY, 0, 0));
        Add(AttributeBytes::New(CKA_CHECK_VALUE, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_START_DATE, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_END_DATE, NULL, 0, 0));
    }
    CATCH_EXCEPTION;
}
