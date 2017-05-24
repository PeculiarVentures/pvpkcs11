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
        // Encode public key info
        ULONG ulEncodedLen;
        if (!CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            &value->Get()->pCertInfo->SubjectPublicKeyInfo,
            NULL,
            &ulEncodedLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }
        Buffer encoded(ulEncodedLen);
        if (!CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            &value->Get()->pCertInfo->SubjectPublicKeyInfo,
            encoded.data(),
            &ulEncodedLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }

        return Digest(
            mechType,
            encoded.data(),
            encoded.size()
        );
    }
    CATCH_EXCEPTION
}

CK_RV X509Certificate::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::X509Certificate::CreateValues(
            pTemplate,
            ulCount
        );

        core::Template tmpl(pTemplate, ulCount);

        Scoped<crypt::Certificate> cert(new crypt::Certificate());
        auto encoded = tmpl.GetBytes(CKA_VALUE, true);
        cert->Import(encoded->data(), encoded->size());
        Assign(cert);

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            AddToMyStorage();
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV X509Certificate::CopyValues(
    Scoped<Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::X509Certificate::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        core::Template tmpl(pTemplate, ulCount);

        X509Certificate* original = dynamic_cast<X509Certificate*>(object.get());
        
        auto cert = original->value->Duplicate();
        Assign(cert);

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            AddToMyStorage();
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void mscapi::X509Certificate::AddToMyStorage()
{
    try {
        crypt::CertStore store;
        store.Open(PV_STORE_NAME_MY);

        auto cert = value;

        // Add KEY_PROV_INFO
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key;
        DWORD dwKeySpec;
        BOOL fFree;

        auto certSpkiHash = GetPublicKeyHash(CKM_SHA_1);
        ncrypt::Provider provider;
        provider.Open(MS_KEY_STORAGE_PROVIDER, 0);
        auto provKeyNames = provider.GetKeyNames(NCRYPT_SILENT_FLAG);
        for (ULONG i = 0; i < provKeyNames->size(); i++) {
            auto provKeyName = provKeyNames->at(i);
            auto key = provider.OpenKey(provKeyName->pszName, provKeyName->dwLegacyKeySpec, 0);
            auto keySpkiHash = key->GetId();
            if (!memcmp(certSpkiHash->data(), keySpkiHash->data(), keySpkiHash->size
            ())) {
                provKeyName->dwFlags;
                CRYPT_KEY_PROV_INFO keyProvInfo;
                
                keyProvInfo.pwszContainerName = provKeyName->pszName;
                keyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;
                keyProvInfo.dwProvType = 0;
                keyProvInfo.dwFlags = provKeyName->dwFlags;
                keyProvInfo.cProvParam = 0;
                keyProvInfo.rgProvParam = NULL;
                keyProvInfo.dwKeySpec = 0;

                if (!CertSetCertificateContextProperty(cert->Get(), CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
                    THROW_MSCAPI_EXCEPTION();
                }
            }
        }

        store.AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::X509Certificate::Destroy()
{
    try {
        value->DeleteFromStore();

        return CKR_OK;
    }
    CATCH_EXCEPTION
}