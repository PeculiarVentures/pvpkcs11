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
    if (handle) {
        NCryptFreeObject(handle);
        handle = NULL;
    }
}

void Key::Finalize(
    ULONG dwFlags
)
{
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
    try {
        NTSTATUS status = NCryptDeleteKey(handle, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
    }
    CATCH_EXCEPTION
}

/*
    Calculate ID for key <HASH_SHA1(SPKI)>
*/
Scoped<Buffer> Key::GetId()
{
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
        Scoped<CERT_PUBLIC_KEY_INFO> spki(pSpki, free);

        ULONG ulEncodedLen;
        if (!CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            pSpki,
            NULL,
            &ulEncodedLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }
        Buffer encoded(ulEncodedLen);
        if (!CryptEncodeObject(
            X509_ASN_ENCODING,
            X509_PUBLIC_KEY_INFO,
            pSpki,
            encoded.data(),
            &ulEncodedLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }

        return DIGEST_SHA1(encoded.data(), encoded.size());
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
    try {
        // copy key to new Provider
        auto blob = key->ExportKey(pszBlobType, 0);
        auto keyAlforithm = key->GetBytesW(NCRYPT_ALGORITHM_PROPERTY);

        auto nkey = provider->CreatePersistedKey(keyAlforithm->c_str(), pszContainerName, 0, 0);
        nkey->SetParam(BCRYPT_RSAFULLPRIVATE_BLOB, blob->data(), blob->size(), NCRYPT_PERSIST_FLAG);

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

        return nkey;
    }
    CATCH_EXCEPTION
}