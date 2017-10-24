#include "provider.h"

#include "../../core/converter.h"
#include "../helper.h"
#include "../bcrypt/provider.h"
#include "../crypt/cert_store.h"

using namespace ncrypt;

void ncrypt::Provider::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Close();
    }
    CATCH_EXCEPTION
}

void ncrypt::Provider::Open(LPCWSTR pszProvName, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Close();

        NTSTATUS status = NCryptOpenStorageProvider(Ref(), pszProvName, 0);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptOpenStorageProvider");
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Provider::Close()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            NCryptFreeObject(Get());
        }
    }
    CATCH_EXCEPTION
}

Scoped<Key> ncrypt::Provider::CreatePersistedKey(
    _In_     LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_     DWORD   dwLegacyKeySpec,
    _In_     DWORD   dwFlags
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        NCRYPT_KEY_HANDLE hKey = NULL;

        NTSTATUS status = NCryptCreatePersistedKey(
            Get(),
            &hKey,
            pszAlgId,
            pszKeyName,
            dwLegacyKeySpec,
            dwFlags
        );
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptCreatePersistedKey");
        }

        return Scoped<Key>(new Key(hKey));
    }
    CATCH_EXCEPTION
}

Scoped<Key> ncrypt::Provider::GetKey(LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Key> key(new Key);
        NTSTATUS status = NCryptOpenKey(Get(), key->Ref(), pszKeyName, dwLegacyKeySpec, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptOpenKey");
        }

        return key;
    }
    CATCH_EXCEPTION
}

void LinkKeyToCertificate(
    Scoped<Key>     key
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        crypt::CertificateStorage store;
        store.Open(PV_STORE_NAME_MY);
        auto certs = store.GetCertificates();
        for (ULONG i = 0; i < certs->size(); i++) {
            auto cert = certs->at(i);

            if (!cert->HasPrivateKey()) {
                auto keySpki = ExportPublicKeyInfo(key->Get());
                if (CertComparePublicKeyInfo(X509_ASN_ENCODING, keySpki.get(), &cert->Get()->pCertInfo->SubjectPublicKeyInfo)) {
                    // Create key
                    CRYPT_KEY_PROV_INFO keyProvInfo;

                    auto containerName = key->GetStringW(NCRYPT_NAME_PROPERTY);

                    keyProvInfo.pwszContainerName = (LPWSTR)containerName->c_str();
                    keyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;
                    keyProvInfo.dwProvType = 0;
                    keyProvInfo.dwFlags = 0;
                    keyProvInfo.cProvParam = 0;
                    keyProvInfo.rgProvParam = NULL;
                    keyProvInfo.dwKeySpec = AT_KEYEXCHANGE;

                    if (!CertSetCertificateContextProperty(cert->Get(), CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
                        THROW_MSCAPI_EXCEPTION("CertSetCertificateContextProperty");
                    }
                }
            }
        }
    }
    CATCH_EXCEPTION
}

Scoped<Key> ncrypt::Provider::SetKey(Key* key, LPCWSTR pszBlobType, LPCWSTR pszContainerName, bool extractable)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        // copy key to new Provider
        auto blob = key->Export(pszBlobType);
        auto keyAlgorithm = key->GetStringW(NCRYPT_ALGORITHM_PROPERTY);

        auto nkey = CreatePersistedKey(keyAlgorithm->c_str(), pszContainerName, AT_KEYEXCHANGE, 0);
        nkey->SetBytes(pszBlobType, blob, NCRYPT_PERSIST_FLAG);
        
        // Set CNG properties
        // Extractable
        if (extractable || !pszContainerName) {
            // All memory keys must be extractable. It allows to save them if needed to storage
            nkey->SetNumber(NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_PERSIST_FLAG);
        }
        // Key usage
        auto attrKeyUsage = key->GetNumber(NCRYPT_KEY_USAGE_PROPERTY);
        nkey->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, attrKeyUsage, NCRYPT_PERSIST_FLAG);

        nkey->Finalize();

        LinkKeyToCertificate(nkey);

        return nkey;
    }
    CATCH_EXCEPTION
}

Scoped<NCryptKeyNameList> ncrypt::Provider::GetKeyNames(
    ULONG               dwFlags
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status;

        void* ptr = NULL;

        Scoped<NCryptKeyNameList> res(new NCryptKeyNameList());

        while (!status) {
            NCryptKeyName* pKeyName;
            status = NCryptEnumKeys(Get(), NULL, &pKeyName, &ptr, dwFlags);
            if (!status && pKeyName) {
                res->push_back(Scoped<NCryptKeyName>(pKeyName, NCryptFreeBuffer));
            }
        }
        if (ptr) {
            NCryptFreeBuffer(ptr);
        }
        if (status && status != NTE_NO_MORE_ITEMS) {
            THROW_NT_EXCEPTION(status, "NCryptEnumKeys");
        }

        return res;
    }
    CATCH_EXCEPTION
};

Scoped<std::wstring> ncrypt::Provider::GenerateRandomName()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        // Generate random value
        bcrypt::Provider bProv;
        Scoped<Buffer> rnd = bProv.GenerateRandom(20);

        Scoped<std::string> hexStr = core::Converter::ToHex(rnd);
        return Scoped<std::wstring>(new std::wstring(hexStr->begin(), hexStr->end()));
    }
    CATCH_EXCEPTION
}
