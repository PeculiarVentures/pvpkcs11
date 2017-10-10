#include "../ncrypt.h"
#include "../crypt/crypt.h"
#include "../crypto.h"

using namespace ncrypt;

Key::Key(
    NCRYPT_KEY_HANDLE handle
)
{
    this->handle = handle;
}

Key::~Key()
{
	LOGGER_FUNCTION_BEGIN;

    if (handle) {
        NCryptFreeObject(handle);
        handle = NULL;
    }
}

void Key::Finalize(
    ULONG dwFlags
)
{
	LOGGER_FUNCTION_BEGIN;

    NTSTATUS status = NCryptFinalizeKey(handle, dwFlags);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
}

Scoped<Buffer> Key::ExportKey(
    _In_    LPCWSTR pszBlobType,
    _In_    DWORD   dwFlags
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status;

        Scoped<Buffer> blob(new Buffer());
        ULONG ulBlobLen;
        status = NCryptExportKey(handle, NULL, pszBlobType, NULL, NULL, 0, &ulBlobLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
        blob->resize(ulBlobLen);
        status = NCryptExportKey(handle, NULL, pszBlobType, NULL, blob->data(), blob->size(), &ulBlobLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        return blob;
    }
    CATCH_EXCEPTION
}

void Key::Delete(
    ULONG           dwFlags
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = NCryptDeleteKey(handle, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
    }
    CATCH_EXCEPTION
}

Scoped<CERT_PUBLIC_KEY_INFO> Key::GetPublicKeyInfo()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        ULONG spkiLen;
        if (!CryptExportPublicKeyInfo(
            handle,
            0,
            X509_ASN_ENCODING,
            NULL,
            &spkiLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }
        PCERT_PUBLIC_KEY_INFO pSpki = (PCERT_PUBLIC_KEY_INFO)malloc(spkiLen);
        if (!CryptExportPublicKeyInfo(
            handle,
            0,
            X509_ASN_ENCODING,
            pSpki,
            &spkiLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }
        return Scoped<CERT_PUBLIC_KEY_INFO>(pSpki, free);
    }
    CATCH_EXCEPTION
}

/*
    Calculate ID for key <HASH_SHA1(SPKI)>
*/
Scoped<Buffer> Key::GetId()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<CERT_PUBLIC_KEY_INFO> spki = GetPublicKeyInfo();

        return DIGEST_SHA1(spki->PublicKey.pbData, spki->PublicKey.cbData);
    }
    CATCH_EXCEPTION
}

void LinkKeyToCertificate(
    Key*            key
) 
{
	LOGGER_FUNCTION_BEGIN;

	try {
		crypt::CertStore store;
		store.Open(PV_STORE_NAME_MY);
		auto certs = store.GetCertificates();
		for (ULONG i = 0; i < certs.size(); i++) {
			auto cert = certs.at(i);

			if (!cert->HasProperty(CERT_KEY_PROV_INFO_PROP_ID)) {
				auto keySpki = key->GetPublicKeyInfo().get();
				if (CertComparePublicKeyInfo(X509_ASN_ENCODING, keySpki, &cert->Get()->pCertInfo->SubjectPublicKeyInfo)) {
					// Create key 
					CRYPT_KEY_PROV_INFO keyProvInfo;

					auto containerName = key->GetBytesW(NCRYPT_NAME_PROPERTY);

					keyProvInfo.pwszContainerName = (LPWSTR) containerName->c_str();
					keyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;
					keyProvInfo.dwProvType = 0;
					keyProvInfo.dwFlags = 0;
					keyProvInfo.cProvParam = 0;
					keyProvInfo.rgProvParam = NULL;
					keyProvInfo.dwKeySpec = 0;

					if (!CertSetCertificateContextProperty(cert->Get(), CERT_KEY_PROV_INFO_PROP_ID, 0, &keyProvInfo)) {
						THROW_MSCAPI_EXCEPTION();
					}
				}
			}
		}
	}
	CATCH_EXCEPTION
}

Scoped<Key> ncrypt::CopyKeyToProvider(
    Key*                key,
    LPCWSTR             pszBlobType,
    Provider*           provider,
    LPCWSTR             pszContainerName,
    bool                extractable
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        // copy key to new Provider
        auto blob = key->ExportKey(pszBlobType, 0);
        auto keyAlgorithm = key->GetBytesW(NCRYPT_ALGORITHM_PROPERTY);

        auto nkey = provider->CreatePersistedKey(keyAlgorithm->c_str(), pszContainerName, 0, 0);
        nkey->SetParam(pszBlobType, blob->data(), blob->size(), NCRYPT_PERSIST_FLAG);

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

        LinkKeyToCertificate(nkey.get());

        return nkey;
    }
    CATCH_EXCEPTION
}
