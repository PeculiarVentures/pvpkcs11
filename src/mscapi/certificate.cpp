#include "certificate.h"

#include "crypt/crypt.h"
#include "crypto.h"

using namespace mscapi;

void X509Certificate::Assign(
    Scoped<crypt::Certificate>        cert
)
{
    try {
        value = cert;
        auto context = cert->Get();

        // CKA_SUBJECT
        ItemByType(CKA_SUBJECT)->To<core::AttributeBytes>()->Set(
            context->pCertInfo->Subject.pbData,
            context->pCertInfo->Subject.cbData
        );
        // CKA_ISSUER
        ItemByType(CKA_ISSUER)->To<core::AttributeBytes>()->Set(
            context->pCertInfo->Issuer.pbData,
            context->pCertInfo->Issuer.cbData
        );
        // CKA_ID
        auto hash = GetPublicKeyHash(CKM_SHA_1);
        ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set(
            hash->data(),
            hash->size()
        );
        // CKA_CHECK_VALUE
        ItemByType(CKA_CHECK_VALUE)->To<core::AttributeBytes>()->Set(
            hash->data(),
            3
        );
        // CKA_SERIAL_NUMBER
        ItemByType(CKA_SERIAL_NUMBER)->To<core::AttributeBytes>()->Set(
            context->pCertInfo->SerialNumber.pbData,
            context->pCertInfo->SerialNumber.cbData
        );
        // CKA_VALUE
        ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->Set(
            context->pbCertEncoded,
            context->cbCertEncoded
        );
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> X509Certificate::GetPublicKeyHash(
    CK_MECHANISM_TYPE       mechType
)
{
    try {
        return Digest(
            mechType,
            value->Get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
            value->Get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData
        );
    }
    CATCH_EXCEPTION
}