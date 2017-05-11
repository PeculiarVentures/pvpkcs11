#include "../ncrypt.h"

using namespace ncrypt;

void Provider::Open(
    _In_opt_ LPCWSTR pszProviderName,
    _In_    DWORD   dwFlags
)
{
    NTSTATUS status = NCryptOpenStorageProvider(
        &handle,
        pszProviderName,
        dwFlags
    );
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
}

Provider::~Provider()
{
    if (handle) {
        NCryptFreeObject(handle);
        handle = NULL;
    }
}

Scoped<Key> Provider::OpenKey(
    _In_     LPCWSTR pszKeyName,
    _In_opt_ DWORD   dwLegacyKeySpec,
    _In_     DWORD   dwFlags
)
{
    NCRYPT_KEY_HANDLE hKey;

    NTSTATUS status = NCryptOpenKey(
        handle,
        &hKey,
        pszKeyName,
        dwLegacyKeySpec,
        dwFlags
    );
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
    return Scoped<Key>(new Key(hKey));
}

Scoped<Key> Provider::TranslateHandle(
    _In_    HCRYPTPROV hLegacyProv,
    _In_opt_ HCRYPTKEY hLegacyKey,
    _In_opt_ DWORD  dwLegacyKeySpec,
    _In_    DWORD   dwFlags
)
{
    NCRYPT_PROV_HANDLE hProvider;

    NCRYPT_KEY_HANDLE hKey;
    NTSTATUS status = NCryptTranslateHandle(&hProvider, &hKey, hLegacyProv, hLegacyKey, dwLegacyKeySpec, dwFlags);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
    NCryptFreeObject(hProvider);
    return Scoped<Key>(new Key(hKey));
}

Scoped<Key> Provider::GenerateKeyPair(
    _In_     LPCWSTR pszAlgId,
    _In_opt_ LPCWSTR pszKeyName,
    _In_     DWORD   dwLegacyKeySpec,
    _In_     DWORD   dwFlags
)
{
    NCRYPT_KEY_HANDLE hKey;

    NTSTATUS status = NCryptCreatePersistedKey(
        handle,
        &hKey,
        pszAlgId,
        pszKeyName,
        dwLegacyKeySpec,
        dwFlags
    );
    if (status) {
        THROW_NT_EXCEPTION(status);
    }

    return Scoped<Key>(new Key(hKey));
}