#include "data.h"

#include "crypt/crypt.h"
#include "crypto.h"

using namespace mscapi;

Scoped<Buffer> GetHash(CK_MECHANISM_TYPE mechanismType, PUCHAR pbData, ULONG cbData)
{
    try {
        Scoped<Buffer> buffer(new Buffer(256));
        CK_ULONG digestLength;
        CryptoDigest digest;
        CK_MECHANISM mechanism = { mechanismType, NULL };
        digest.Init(&mechanism);
        digest.Once(
            pbData,
            cbData,
            buffer->data(),
            &digestLength
        );
        buffer->resize(digestLength);

        return buffer;
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount
)
{
    try {
        core::Data::CreateValues(
            pTemplate,
            ulCount
        );

        core::Template tmpl(pTemplate, ulCount);
        auto attrValue = tmpl.GetBytes(CKA_VALUE, true);

        // try to decode request
        Buffer decoded;
        ULONG ulDecodedLen;
        if (!CryptDecodeObject(
            CRYPT_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            attrValue->data(),
            attrValue->size(),
            CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &ulDecodedLen
        )) {
            THROW_MSCAPI_ERROR();
        }
        decoded.resize(ulDecodedLen);
        if (!CryptDecodeObject(
            CRYPT_ASN_ENCODING,
            X509_CERT_REQUEST_TO_BE_SIGNED,
            attrValue->data(),
            attrValue->size(),
            CRYPT_DECODE_NOCOPY_FLAG,
            decoded.data(),
            &ulDecodedLen
        )) {
            THROW_MSCAPI_ERROR();
        }

        CERT_REQUEST_INFO* requestInfo = (CERT_REQUEST_INFO*)decoded.data();

        // create PCCERT_CONTEXT for request keeping
        PCCERT_CONTEXT cert = CertCreateSelfSignCertificate(
            NULL,
            &requestInfo->Subject,
            CERT_CREATE_SELFSIGN_NO_KEY_INFO | CERT_CREATE_SELFSIGN_NO_SIGN,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (!cert) {
            THROW_MSCAPI_ERROR();
        }

        this->context = Scoped<CERT_CONTEXT>((PCERT_CONTEXT)cert, CertFreeCertificateContext);

        {
            CRYPT_DATA_BLOB dataBlob = {
                attrValue->size(), // cbData
                attrValue->data()  // pbData
            };
            if (!CertSetCertificateContextProperty(cert, CERT_PV_REQUEST, 0, &dataBlob)) {
                THROW_MSCAPI_ERROR();
            }
        }

        {
            auto hash = GetHash(CKM_SHA_1, requestInfo->SubjectPublicKeyInfo.PublicKey.pbData, requestInfo->SubjectPublicKeyInfo.PublicKey.cbData);
            CRYPT_DATA_BLOB dataBlob = {
                hash->size(), // cbData
                hash->data()  // pbData
            };
            if (!CertSetCertificateContextProperty(cert, CERT_PV_ID, 0, &dataBlob)) {
                THROW_MSCAPI_ERROR();
            }
        }

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            auto requestStore = Scoped<crypt::CertStore>(new crypt::CertStore());
            requestStore->Open("REQUEST");

            requestStore->AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
        }
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::CopyValues(
    Scoped<Object>    object,   
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount   
)
{
    try {
        core::Data::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        X509CertificateRequest* original = dynamic_cast<X509CertificateRequest*>(object.get());
        if (!original) {
            THROW_EXCEPTION("Object must be X509CErtificateRequest");
        }

        core::Template tmpl(pTemplate, ulCount);

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            auto requestStore = Scoped<crypt::CertStore>(new crypt::CertStore());
            requestStore->Open("REQUEST");

            requestStore->AddCertificate(original->context.get(), CERT_STORE_ADD_ALWAYS);
        }

        context = original->context;
    }
    CATCH_EXCEPTION
}