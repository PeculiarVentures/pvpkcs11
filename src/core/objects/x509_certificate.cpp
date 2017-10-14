#include "x509_certificate.h"

using namespace core;

X509Certificate::X509Certificate() :
    Certificate()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        ItemByType(CKA_CERTIFICATE_TYPE)->To<AttributeNumber>()->Set(CKC_X_509);

        Add(AttributeBytes::New(CKA_SUBJECT, NULL, 0, PVF_1));
        Add(AttributeBytes::New(CKA_ID, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_ISSUER, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_SERIAL_NUMBER, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_VALUE, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_URL, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_HASH_OF_ISSUER_PUBLIC_KEY, NULL, 0, 0));
        Add(AttributeNumber::New(CKA_JAVA_MIDP_SECURITY_DOMAIN, 0, 0));
        Add(AttributeNumber::New(CKA_NAME_HASH_ALGORITHM, CKM_SHA_1, 0));
    }
    CATCH_EXCEPTION
}