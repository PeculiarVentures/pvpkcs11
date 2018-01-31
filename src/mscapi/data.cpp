#include "data.h"
#include "crypto.h"
#include "ncrypt/provider.h"
#include "crypt/cert_store.h"

using namespace mscapi;

void X509CertificateRequest::Assign(
    Scoped<crypt::Certificate>  cert
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (cert->HasProperty(CERT_PV_REQUEST) && cert->HasProperty(CERT_PV_ID)) {
            auto propRequest = cert->GetBytes(CERT_PV_REQUEST);

            ItemByType(CKA_VALUE)->SetValue(propRequest->data(), propRequest->size());
            char *label = "X509 Request";
            ItemByType(CKA_LABEL)->SetValue(label, strlen(label));
            auto propObjectId = cert->GetBytes(CERT_PV_ID);
            ItemByType(CKA_OBJECT_ID)->SetValue(propObjectId->data(), propObjectId->size());

            this->cert = cert;
        }
        else {
            THROW_EXCEPTION("Wrong certificate. Cannot get required properties CERT_PV_REQUEST and CERT_PV_ID");
        }
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Data::CreateValues(
            pTemplate,
            ulCount
        );

        CERT_REQUEST_INFO* requestInfo = NULL;

        core::Template tmpl(pTemplate, ulCount);
        Scoped<Buffer> attrValue = tmpl.GetBytes(CKA_VALUE, true);
        Scoped<Buffer> attrObjectId = tmpl.GetBytes(CKA_OBJECT_ID, false);

#pragma region Decode request
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
            THROW_MSCAPI_EXCEPTION("CryptDecodeObject");
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
            THROW_MSCAPI_EXCEPTION("CryptDecodeObject");
        }
        requestInfo = (CERT_REQUEST_INFO*)decoded.data();
#pragma endregion

#pragma region Create PCCERT_CONTEXT for request keeping
        PCCERT_CONTEXT context = CertCreateSelfSignCertificate(
            NULL,
            &requestInfo->Subject,
            CERT_CREATE_SELFSIGN_NO_SIGN | CERT_CREATE_SELFSIGN_NO_KEY_INFO,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (!context) {
            THROW_MSCAPI_EXCEPTION("CertCreateSelfSignCertificate");
        }
        cert = Scoped<crypt::Certificate>(new crypt::Certificate(context));
#pragma endregion

#pragma region Set attributes
        cert->SetBytes(CERT_PV_REQUEST, attrValue);
        cert->SetBytes(CERT_PV_ID, attrObjectId);
#pragma endregion

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
#pragma region Add certificate to storage
            auto requestStore = Scoped<crypt::CertificateStorage>(new crypt::CertificateStorage);
            requestStore->Open(PV_STORE_NAME_REQUEST);

            requestStore->AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
#pragma endregion
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::CopyValues(
    Scoped<Object>    object,
    CK_ATTRIBUTE_PTR  pTemplate,
    CK_ULONG          ulCount
)
{
    LOGGER_FUNCTION_BEGIN;

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
            cert = original->cert->Duplicate();

            auto requestStore = Scoped<crypt::CertificateStorage>(new crypt::CertificateStorage);
            requestStore->Open(PV_STORE_NAME_REQUEST);

            requestStore->AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::Destroy()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        cert->DeleteFromStore();

        return CKR_OK;
    }
    CATCH_EXCEPTION
}