#include "certificate.h"

#include "crypt/crypt.h"
#include "crypto.h"

using namespace mscapi;

#define CHAIN_ITEM_TYPE_CERT                1
#define CHAIN_ITEM_TYPE_CRL                 2

/*
    Returns DER collection of certificates

    CK_ULONG itemType
    CK_ULONG itemSize
    CK_BYTE itemValue[certSize]
    ...
    CK_ULONG itemType
    CK_ULONG itemSize
    CK_BYTE itemValue[certSize]
*/
Scoped<Buffer> GetCertificateChain
(
    crypt::Certificate*     cert       // certificate
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        PCCERT_CHAIN_CONTEXT     pChainContext = NULL;
        CERT_CHAIN_PARA          ChainPara;
        ChainPara.cbSize = sizeof(CERT_CHAIN_PARA);
        ChainPara.RequestedUsage.dwType = USAGE_MATCH_TYPE_AND;
        ChainPara.RequestedUsage.Usage.cUsageIdentifier = 0;
        ChainPara.RequestedUsage.Usage.rgpszUsageIdentifier = NULL;

        ChainPara.dwUrlRetrievalTimeout = 20000;
        ChainPara.dwRevocationFreshnessTime = 60;
        ChainPara.fCheckRevocationFreshnessTime = TRUE;
        ChainPara.RequestedIssuancePolicy.dwType = USAGE_MATCH_TYPE_AND;
        ChainPara.RequestedIssuancePolicy. Usage.cUsageIdentifier = 0;
        ChainPara.RequestedIssuancePolicy.Usage.rgpszUsageIdentifier = NULL;
        ChainPara.pftCacheResync = NULL;
        ChainPara.pStrongSignPara = NULL;
        ChainPara.dwStrongSignFlags = 0;


        DWORD dwFlags = CERT_CHAIN_REVOCATION_CHECK_CHAIN;

        if (!CertGetCertificateChain(
            NULL,
            cert->Get(),
            NULL,
            NULL,
            &ChainPara,
            dwFlags,
            NULL,
            &pChainContext))
        {
            THROW_MSCAPI_EXCEPTION("CertGetCertificateChain");
        }

        if (!pChainContext) {
            THROW_EXCEPTION("pChainContext is NULL");
        }

        std::vector<PCCERT_CONTEXT> certs(0);
        std::vector<PCCRL_CONTEXT> crls(0);

        if (!pChainContext->cChain) {
            CertFreeCertificateChain(pChainContext);
            THROW_EXCEPTION("No one simple chain context");
        }
        auto chain = pChainContext->rgpChain[0];
        for (int i = 0; i < chain->cElement; i++) {
            auto element = chain->rgpElement[i];
            certs.push_back(element->pCertContext);

            if (element->pRevocationInfo && element->pRevocationInfo->pCrlInfo) {
                if (element->pRevocationInfo->pCrlInfo->pBaseCrlContext) {
                    crls.push_back(element->pRevocationInfo->pCrlInfo->pBaseCrlContext);
                }
                if (element->pRevocationInfo->pCrlInfo->pDeltaCrlContext) {
                    crls.push_back(element->pRevocationInfo->pCrlInfo->pDeltaCrlContext);
                }
            }
        }

        CK_ULONG ulDataLen = 0;
        Scoped<Buffer> res(new Buffer);
        for (int i = 0; i < certs.size(); i++) {
            CK_ULONG start = ulDataLen;
            auto pCert = certs.at(i);
            // itemType
            res->resize(++ulDataLen);
            auto itemType = CHAIN_ITEM_TYPE_CERT;
            // itemSize
            ulDataLen += sizeof(CK_ULONG);
            // itemValue
            ulDataLen += pCert->cbCertEncoded;
            res->resize(ulDataLen);
            CK_BYTE_PTR pCertData = res->data() + start;
            memcpy(pCertData, &itemType, 1);
            memcpy(pCertData + 1, &pCert->cbCertEncoded, sizeof(CK_ULONG));
            memcpy(pCertData + 1 + sizeof(CK_ULONG), pCert->pbCertEncoded, pCert->cbCertEncoded);
        }

        for (int i = 0; i < crls.size(); i++) {
            CK_ULONG start = ulDataLen;
            auto pCrl = crls.at(i);
            // itemType
            res->resize(++ulDataLen);
            auto itemType = CHAIN_ITEM_TYPE_CRL;
            // itemSize
            ulDataLen += sizeof(CK_ULONG);
            // itemValue
            ulDataLen += pCrl->cbCrlEncoded;
            res->resize(ulDataLen);
            CK_BYTE_PTR pCrlData = res->data() + start;
            memcpy(pCrlData, &itemType, 1);
            memcpy(pCrlData + 1, &pCrl->cbCrlEncoded, sizeof(CK_ULONG));
            memcpy(pCrlData + 1 + sizeof(CK_ULONG), pCrl->pbCrlEncoded, pCrl->cbCrlEncoded);
        }

        CertFreeCertificateChain(pChainContext);

        return res;
    }
    CATCH_EXCEPTION
}

mscapi::X509Certificate::X509Certificate()
    : core::X509Certificate()
{
	LOGGER_FUNCTION_BEGIN;

    Add(core::AttributeBytes::New(CKA_X509_CHAIN, NULL, 0, PVF_2));
}

void mscapi::X509Certificate::Assign(
    Scoped<crypt::Certificate>        cert
)
{
	LOGGER_FUNCTION_BEGIN;

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

Scoped<Buffer> mscapi::X509Certificate::GetPublicKeyHash(
    CK_MECHANISM_TYPE       mechType
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        return Digest(
            mechType,
			value->Get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
			value->Get()->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData
        );
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::X509Certificate::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

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

CK_RV mscapi::X509Certificate::CopyValues(
    Scoped<Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

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
	LOGGER_FUNCTION_BEGIN;

    try {
        crypt::CertStore store;
        store.Open(PV_STORE_NAME_MY);

        auto cert = value;

        // Add KEY_PROV_INFO
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE key;
        DWORD dwKeySpec;
        BOOL fFree;

        // get SHA1 of certificate SPKI
        auto certSpkiHash = GetPublicKeyHash(CKM_SHA_1);
        ncrypt::Provider provider;
        provider.Open(MS_KEY_STORAGE_PROVIDER, 0);
        // Looking for equal public key hash through all CNG containers
        auto provKeyNames = provider.GetKeyNames(NCRYPT_SILENT_FLAG);
        for (ULONG i = 0; i < provKeyNames->size(); i++) {
            auto provKeyName = provKeyNames->at(i);
            auto key = provider.OpenKey(provKeyName->pszName, provKeyName->dwLegacyKeySpec, 0);
            Scoped<Buffer> keySpkiHash;
            try {
                keySpkiHash = key->GetId();
            }
            catch (...) {
                // Cannot get id from key. Key can be from token
                // TODO: To check another way to get ID from key
                continue;
            }
            // compare hashes
            if (!memcmp(certSpkiHash->data(), keySpkiHash->data(), keySpkiHash->size
            ())) {
                // Create key info
                CRYPT_KEY_PROV_INFO keyProvInfo;

                keyProvInfo.pwszContainerName = provKeyName->pszName;
                keyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;
                keyProvInfo.dwProvType = 0;
                keyProvInfo.dwFlags = provKeyName->dwFlags;
                keyProvInfo.cProvParam = 0;
                keyProvInfo.rgProvParam = NULL;
                keyProvInfo.dwKeySpec = 0;

                if (!CertSetCertificateContextProperty(cert->Get(), CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
                    THROW_MSCAPI_EXCEPTION("CertSetCertificateContextProperty");
                }
            }
        }

        store.AddCertificate(cert, CERT_STORE_ADD_ALWAYS);
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::X509Certificate::Destroy()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        value->DeleteFromStore();

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::X509Certificate::GetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        switch (attr->type) {
        case CKA_X509_CHAIN: {
            auto certs = GetCertificateChain(value.get());
            ItemByType(CKA_X509_CHAIN)->SetValue(certs->data(), certs->size());
            break;
        }
        default:
            core::Object::GetValue(attr);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}