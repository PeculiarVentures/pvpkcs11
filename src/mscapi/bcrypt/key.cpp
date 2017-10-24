#include "key.h"
#include "../helper.h"

using namespace bcrypt;

void bcrypt::Key::Dispose() {
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            BCryptDestroyKey(Get());
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

Scoped<Key> bcrypt::Key::Duplicate()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Key> key(new Key());

        NTSTATUS status = BCryptDuplicateKey(Get(), key->Ref(), NULL, 0, 0);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptDuplicateKey");
        }

        return key;
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::ImportPublicKeyInfo(DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        BCRYPT_KEY_HANDLE hKey = NULL;

        if (!CryptImportPublicKeyInfoEx2(dwCertEncodingType, pInfo, dwFlags, NULL, &hKey)) {
            THROW_MSCAPI_EXCEPTION("CryptImportPublicKeyInfoEx2");
        }

        Set(hKey);
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> bcrypt::Key::Export(LPCWSTR pszBlobType, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = 0;
        Scoped<Buffer> res(new Buffer(0));
        DWORD resLen = 0;

        status = BCryptExportKey(Get(), NULL, pszBlobType, NULL, 0, &resLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptExportKey");
        }

        res->resize(resLen);

        status = BCryptExportKey(Get(), NULL, pszBlobType, res->data(), res->size(), &resLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptExportKey");
        }

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::wstring> bcrypt::Key::GetAlgorithmName()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return GetStringW(BCRYPT_ALGORITHM_NAME);
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::ChangeMode(LPCWSTR pszMode)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        SetStringW(BCRYPT_CHAINING_MODE, Scoped<std::wstring>(new std::wstring(pszMode)));
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::GetParam(LPCWSTR pszProperty, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = BCryptGetProperty(Get(), pszProperty, pbData, *pdwDataLen, pdwDataLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptGetProperty");
        }
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::SetParam(LPCWSTR pszProperty, PBYTE pbData, DWORD dwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = BCryptSetProperty(Get(), pszProperty, pbData, dwDataLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptSetProperty");
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> bcrypt::Key::GetBytes(LPCWSTR pszProperty, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> res(new Buffer(0));
        DWORD dwResLen = 0;

        GetParam(pszProperty, NULL, &dwResLen, dwFlags);
        res->resize(dwResLen);
        GetParam(pszProperty, res->data(), &dwResLen, dwFlags);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> bcrypt::Key::GetString(LPCWSTR pszProperty, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(pszProperty, dwFlags);

        return Scoped<std::string>(new std::string((PCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

Scoped<std::wstring> bcrypt::Key::GetStringW(LPCWSTR pszProperty, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(pszProperty, dwFlags);

        return Scoped<std::wstring>(new std::wstring((PWCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

DWORD bcrypt::Key::GetNumber(LPCWSTR pszProperty, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        DWORD res = 0;
        DWORD dwResLen = sizeof(DWORD);

        GetParam(pszProperty, (PBYTE)&res, &dwResLen, dwFlags);

        return res;
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::SetBytes(LPCWSTR pszProperty, Scoped<Buffer> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(pszProperty, value->data(), value->size(), dwFlags);
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::SetString(LPCWSTR pszProperty, Scoped<std::string> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(pszProperty, (PBYTE)value->c_str(), value->length(), dwFlags);
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::SetStringW(LPCWSTR pszProperty, Scoped<std::wstring> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetString(pszProperty, Scoped<std::string>(new std::string(value->begin(), value->end())), dwFlags);
    }
    CATCH_EXCEPTION
}

void bcrypt::Key::SetNumber(LPCWSTR pszProperty, DWORD value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(pszProperty, (PBYTE)&value, sizeof(DWORD), dwFlags);
    }
    CATCH_EXCEPTION
}
