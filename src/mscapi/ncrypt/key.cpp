#include "key.h"
#include "../helper.h"
#include "../crypto.h"
#include "provider.h"

using namespace ncrypt;

void ncrypt::Key::Dispose() {
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            NCryptFreeObject(Get());
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::Open(PCRYPT_KEY_PROV_INFO info)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Dispose();

        Provider prov;
        prov.Open(info->pwszProvName, 0);

        NTSTATUS status = NCryptOpenKey(prov.Get(), Ref(), info->pwszContainerName, info->dwKeySpec, 0);
        if (status) {
            std::wstring wstrContainerName(info->pwszContainerName);
            std::string strContainerName(wstrContainerName.begin(), wstrContainerName.end());
            LOGGER_ERROR("Cannot open key '%s' from '%s'", strContainerName.c_str(), prov.GetProviderName()->c_str());
            THROW_NT_EXCEPTION(status, "NCryptOpenKey");
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::Open(LPCWSTR pszProvName, LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Dispose();

        Provider prov;
        prov.Open(pszProvName, 0);

        NTSTATUS status = NCryptOpenKey(prov.Get(), Ref(), pszKeyName, dwLegacyKeySpec, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptOpenKey");
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::GetParam(LPCWSTR pszProperty, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = NCryptGetProperty(Get(), pszProperty, pbData, *pdwDataLen, pdwDataLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptGetProperty");
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::SetParam(LPCWSTR pszProperty, PBYTE pbData, DWORD dwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = NCryptSetProperty(Get(), pszProperty, pbData, dwDataLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptSetProperty");
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> ncrypt::Key::GetBytes(LPCWSTR pszProperty)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> res(new Buffer(0));
        DWORD dwResLen = 0;

        GetParam(pszProperty, NULL, &dwResLen);
        res->resize(dwResLen);
        GetParam(pszProperty, res->data(), &dwResLen);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> ncrypt::Key::GetString(LPCWSTR pszProperty)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(pszProperty);

        return Scoped<std::string>(new std::string((PCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

Scoped<std::wstring> ncrypt::Key::GetStringW(LPCWSTR pszProperty)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(pszProperty);

        return Scoped<std::wstring>(new std::wstring((PWCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

DWORD ncrypt::Key::GetNumber(LPCWSTR pszProperty)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        DWORD res = 0;
        DWORD dwResLen = sizeof(DWORD);

        GetParam(pszProperty, (PBYTE)&res, &dwResLen);

        return res;
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::SetBytes(LPCWSTR pszProperty, Scoped<Buffer> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(
            pszProperty,
            value.get() ? value->data() : NULL,
            value.get() ? value->size() : 0,
            dwFlags
        );
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::SetString(LPCWSTR pszProperty, Scoped<std::string> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(pszProperty, (PBYTE)value->c_str(), value->length(), dwFlags);
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::SetStringW(LPCWSTR pszProperty, Scoped<std::wstring> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetString(pszProperty, Scoped<std::string>(new std::string(value->begin(), value->end())), dwFlags);
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::SetNumber(LPCWSTR pszProperty, DWORD value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(pszProperty, (PBYTE)&value, sizeof(DWORD), dwFlags);
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> ncrypt::Key::Export(LPCWSTR pszBlobType, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status;

        Scoped<Buffer> blob(new Buffer());
        ULONG ulBlobLen;
        status = NCryptExportKey(Get(), NULL, pszBlobType, NULL, NULL, 0, &ulBlobLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptExportKey");
        }
        blob->resize(ulBlobLen);
        status = NCryptExportKey(Get(), NULL, pszBlobType, NULL, blob->data(), blob->size(), &ulBlobLen, dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptExportKey");
        }

        return blob;
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::Import(LPCWSTR pszBlobType, Scoped<Buffer> data, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NCRYPT_KEY_HANDLE hKey = NULL;

        Provider prov;
        prov.Open(MS_KEY_STORAGE_PROVIDER);

        NTSTATUS status = NCryptImportKey(prov.Get(), NULL, pszBlobType, NULL, &hKey, data->data(), data->size(), dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptImportKey");
        }
        Set(hKey);
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::Delete(DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = NCryptDeleteKey(Get(), dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptDeleteKey");
        }
    }
    CATCH_EXCEPTION
}

void ncrypt::Key::Finalize(DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = NCryptFinalizeKey(Get(), dwFlags);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptFinalizeKey");
        }
    }
    CATCH_EXCEPTION
}

/*
    Calculate ID for key <HASH_SHA1(SPKI)>
*/
Scoped<Buffer> ncrypt::Key::GetID()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<CERT_PUBLIC_KEY_INFO> spki = ExportPublicKeyInfo(Get());

        return DIGEST_SHA1(spki->PublicKey.pbData, spki->PublicKey.cbData);
    }
    CATCH_EXCEPTION
}
