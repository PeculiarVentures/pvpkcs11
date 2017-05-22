#include "../ncrypt.h"
#include "../bcrypt.h"

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

Scoped<Key> Provider::CreatePersistedKey(
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

Scoped<Key> Provider::ImportKey(
    _In_        LPCWSTR             pszBlobType,
    _In_reads_bytes_(cbData) PBYTE  pbData,
    _In_        DWORD               cbData,
    _In_        DWORD               dwFlags
)
{
    try {
        NCRYPT_KEY_HANDLE hKey;

        NTSTATUS status = NCryptImportKey(handle, NULL, pszBlobType, NULL, &hKey, pbData, cbData, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }
        return Scoped<Key>(new Key(hKey));
    }
    CATCH_EXCEPTION
}

Scoped<NCryptKeyNames> Provider::GetKeyNames(
    ULONG               dwFlags
)
{
    try {
        NTSTATUS status;

        void* ptr = NULL;

        Scoped<NCryptKeyNames> res(new NCryptKeyNames());

        while (!status) {
            NCryptKeyName* pKeyName;
            status = NCryptEnumKeys(handle, NULL, &pKeyName, &ptr, dwFlags);
            if (pKeyName) {
                res->push_back(Scoped<NCryptKeyName>(pKeyName, NCryptFreeBuffer));
            }
        }
        if (ptr) {
            NCryptFreeBuffer(ptr);
        }
        if (status && status != NTE_NO_MORE_ITEMS) {
            THROW_NT_EXCEPTION(status);
        }

        return res;
    }
    CATCH_EXCEPTION
};

Scoped<std::wstring> Provider::GenerateRandomName()
{
    try {
        // Generate random value
        Buffer buffer(20);
        NTSTATUS status = BCryptGenRandom(NULL, buffer.data(), buffer.size(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        // Convert value to hex string
        std::string hexString("");
        for (ULONG i = 0; i < buffer.size(); i++) {
            std::string byte("00");
            sprintf((PCHAR)byte.c_str(), "%02X", buffer[i]);
            hexString += byte;
        }

        // Convert string to wstring
        return Scoped<std::wstring>(new std::wstring(hexString.begin(), hexString.end()));
    }
    CATCH_EXCEPTION
}
