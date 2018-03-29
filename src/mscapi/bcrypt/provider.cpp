#include "provider.h"
#include "../helper.h"

using namespace bcrypt;

Scoped<Buffer> bcrypt::Provider::GenerateRandom(DWORD dwOutLen)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = 0;
        Scoped<Buffer> buf(new Buffer(dwOutLen));

        status = BCryptGenRandom(NULL, buf->data(), buf->size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptGenRandom");
        }

        return buf;
    }
    CATCH_EXCEPTION
}

Scoped<Provider> bcrypt::Provider::Create(LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Provider> prov(new Provider);
        prov->Open(pszAlgId, pszImplementation, dwFlags);

        return prov;
    }
    CATCH_EXCEPTION
}

void bcrypt::Provider::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Close();
    }
    CATCH_EXCEPTION;
}

void bcrypt::Provider::Open(LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = 0;
        BCRYPT_ALG_HANDLE hAlg = NULL;

        status = BCryptOpenAlgorithmProvider(&hAlg, pszAlgId, pszImplementation, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptOpenAlgorithmProvider");
        }
        Set(hAlg);
    }
    CATCH_EXCEPTION
}

void bcrypt::Provider::Close(DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = 0;
        if (!IsEmpty()) {
            status = BCryptCloseAlgorithmProvider(Get(), dwFlags);
            if (status) {
                THROW_NT_EXCEPTION(status, "BCryptCloseAlgorithmProvider");
            }

            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

Scoped<bcrypt::Key> bcrypt::Provider::GenerateKey(
    PUCHAR  pbKeyObject,
    ULONG   cbKeyObject,
    PUCHAR  pbSecret,
    ULONG   cbSecret,
    ULONG   dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Key> key;

        NTSTATUS status = BCryptGenerateSymmetricKey(
            Get(),
            key->Ref(),
            pbKeyObject,
            cbKeyObject,
            pbSecret,
            cbSecret,
            dwFlags
        );
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptGenerateSymmetricKey");
        }

        return key;
    }
    CATCH_EXCEPTION
}

Scoped<Key> bcrypt::Provider::ImportKey(
    LPCWSTR             pszBlobType,
    PBYTE               pbData,
    DWORD               cbData,
    DWORD               dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Key> key;
        
        NTSTATUS status = BCryptImportKey(Get(), NULL, pszBlobType, key->Ref(), NULL, 0, pbData, cbData, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptImportKey");
        }
        
        return key;
    }
    CATCH_EXCEPTION
}