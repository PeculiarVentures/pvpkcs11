#include "data.h"

#include "crypt/crypt.h"
#include "crypto.h"

using namespace mscapi;

void X509CertificateRequest::Assign(
    Scoped<crypt::Certificate>  cert
)
{
    try {
        if (cert->HasProperty(CERT_PV_REQUEST) && cert->HasProperty(CERT_PV_ID)) {
            auto propRequest = cert->GetPropertyBytes(CERT_PV_REQUEST);

            ItemByType(CKA_VALUE)->SetValue(propRequest->data(), propRequest->size());
            char *label = "X509 Request";
            ItemByType(CKA_LABEL)->SetValue(label, strlen(label));
            auto propObjectId = cert->GetPropertyBytes(CERT_PV_ID);
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
            THROW_MSCAPI_EXCEPTION();
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
            THROW_MSCAPI_EXCEPTION();
        }

        CERT_REQUEST_INFO* requestInfo = (CERT_REQUEST_INFO*)decoded.data();

        // create PCCERT_CONTEXT for request keeping
        PCCERT_CONTEXT context = CertCreateSelfSignCertificate(
            NULL,
            &requestInfo->Subject,
            CERT_CREATE_SELFSIGN_NO_SIGN,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL
        );

        if (!context) {
            THROW_MSCAPI_EXCEPTION();
        }

        cert = Scoped<crypt::Certificate>(new crypt::Certificate);
        cert->Assign(context);

        // Remove private key for self-signed certificate
        {
            auto keyProvInfo = cert->GetPropertyBytes(CERT_KEY_PROV_INFO_PROP_ID);
            PCRYPT_KEY_PROV_INFO pKeyProvInfo = (PCRYPT_KEY_PROV_INFO)keyProvInfo->data();

            ncrypt::Provider prov;
            prov.Open(MS_KEY_STORAGE_PROVIDER, 0);
            auto requestKey = prov.OpenKey(pKeyProvInfo->pwszContainerName, pKeyProvInfo->dwKeySpec, pKeyProvInfo->dwFlags);
            requestKey->Delete(0);

            // remove CERT_KEY_PROV_INFO property
            if (!CertSetCertificateContextProperty(cert->Get(), CERT_KEY_PROV_INFO_PROP_ID, 0, NULL)) {
                THROW_MSCAPI_EXCEPTION();
            }
        }

        cert->SetPropertyBytes(CERT_PV_REQUEST, attrValue.get());
        auto attrObjectId = tmpl.GetBytes(CKA_OBJECT_ID, false);
        cert->SetPropertyBytes(CERT_PV_ID, attrObjectId.get());

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            auto requestStore = Scoped<crypt::CertStore>(new crypt::CertStore());
            requestStore->Open(PV_STORE_NAME_REQUEST);

            requestStore->AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
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

            auto requestStore = Scoped<crypt::CertStore>(new crypt::CertStore());
            requestStore->Open(PV_STORE_NAME_REQUEST);

            requestStore->AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV X509CertificateRequest::Destroy()
{
    try {
        cert->DeleteFromStore();

        return CKR_OK;
    }
    CATCH_EXCEPTION
}