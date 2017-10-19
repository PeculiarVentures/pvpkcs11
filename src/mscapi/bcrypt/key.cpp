#include "../bcrypt.h"

using namespace bcrypt;

Key::Key(
    BCRYPT_KEY_HANDLE handle
)
{
    this->handle = handle;
}

Key::~Key()
{
    Destroy();
}

void Key::Destroy()
{
    if (handle) {
        BCryptDestroyKey(handle);
        handle = NULL;
    }
}

void Key::Finalize(
    _In_    ULONG   dwFlags
)
{
    NTSTATUS status = BCryptFinalizeKeyPair(handle, dwFlags);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
}

Scoped<Key> Key::Duplicate()
{
    BCRYPT_KEY_HANDLE hKeyCopy;
    NTSTATUS status = BCryptDuplicateKey(handle, &hKeyCopy, NULL, 0, 0);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }

    return Scoped<Key>(new Key(hKeyCopy));
}

Scoped<Algorithm> Key::GetProvider()
{
    try {
        BCRYPT_ALG_HANDLE hAlg;
        ULONG ulHandleLen;
        NTSTATUS status = BCryptGetProperty(handle, BCRYPT_PROVIDER_HANDLE, NULL, 0, &ulHandleLen, 0);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
        hAlg = (BCRYPT_ALG_HANDLE)malloc(ulHandleLen);
        status = BCryptGetProperty(handle, BCRYPT_PROVIDER_HANDLE, (PUCHAR)hAlg, ulHandleLen, &ulHandleLen, 0);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
        return Scoped<Algorithm>(new Algorithm(hAlg));
    }
    CATCH_EXCEPTION
}

Scoped<ncrypt::Key> bcrypt::Key::ToNKey()
{
    NCRYPT_KEY_HANDLE nkey = NULL;

    Scoped<std::wstring> algName = GetStringW(BCRYPT_ALGORITHM_NAME);
    LPWSTR blobType;

    Scoped<Buffer> blobBuffer(new Buffer(0));
    if (algName->compare(BCRYPT_RSA_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_RSA_SIGN_ALGORITHM) == 0) {
        blobBuffer->resize(sizeof(BCRYPT_RSAKEY_BLOB));
        blobType = BCRYPT_RSAPUBLIC_BLOB;
    }
    else if (algName->compare(BCRYPT_ECDH_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDSA_P256_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDSA_P384_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDSA_P521_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDH_P256_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDH_P384_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDH_P521_ALGORITHM) == 0 ||
        algName->compare(BCRYPT_ECDSA_ALGORITHM) == 0) {
        blobBuffer->resize(sizeof(BCRYPT_ECCKEY_BLOB));
        blobType = BCRYPT_ECCPUBLIC_BLOB;
    }
    else {
        std::string name(algName->begin(), algName->end());
        THROW_EXCEPTION("Unsupported algorithm '%s'", name.c_str());
    }

    DWORD blobBufferLen = 0;
    NTSTATUS status = BCryptExportKey(handle, NULL, blobType, NULL, 0, &blobBufferLen, 0);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
    blobBuffer->resize(blobBufferLen);
    status = BCryptExportKey(handle, NULL, blobType, blobBuffer->data(), blobBuffer->size(), &blobBufferLen, 0);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }

    ncrypt::Provider ncryptProv;
    ncryptProv.Open(MS_KEY_STORAGE_PROVIDER, 0);
    status = NCryptImportKey(ncryptProv.Get(), NULL, blobType, NULL, &nkey, blobBuffer->data(), blobBuffer->size(), 0);

    if (status) {
        THROW_NT_EXCEPTION(status);
    }
    
    return Scoped<ncrypt::Key>(new ncrypt::Key(nkey));
}