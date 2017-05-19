#include "certificate.h"

#include "crypto.h"

using namespace mscapi;

X509Certificate::~X509Certificate() {
    Destroy();
}

void X509Certificate::Destroy()
{
    if (context) {
        CertFreeCertificateContext(context);
        context = NULL;
    }
}

void X509Certificate::Assign(
    PCCERT_CONTEXT context
)
{
    try {
        Destroy();
        this->context = context;

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
        CK_MECHANISM digestMechanism = { CKM_SHA_1, NULL };
        auto hash = GetPublicKeyHash(&digestMechanism);
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
    CK_MECHANISM_PTR             pMechanism
)
{
    try {
        Scoped<Buffer> buffer(new Buffer(256));
        CK_ULONG digestLength;
        CryptoDigest digest;
        digest.Init(pMechanism);
        digest.Once(
            context->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
            context->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
            buffer->data(),
            &digestLength
        );
        buffer->resize(digestLength);
        return buffer;
    }
    CATCH_EXCEPTION
}