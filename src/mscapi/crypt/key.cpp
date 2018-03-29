#include "key.h"
#include "../helper.h"

using namespace crypt;

/*
Scoped<Key> crypt::Key::Generate(
    Scoped<Provider>  prov,
    ALG_ID            uiAlgId,
    DWORD             dwFlags
)
{
    HCRYPTKEY hNewKey = NULL;
    if (!CryptGenKey(prov->Get(), uiAlgId, dwFlags, &hNewKey)) {
        THROW_MSCAPI_EXCEPTION("CryptGenKey");
    }

    Scoped<Key> result(new Key(hNewKey));
    return result;
}
*/

void crypt::Key::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            CryptReleaseContext(Get(), 0);
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

void crypt::Key::Open(PCRYPT_KEY_PROV_INFO info)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!info) {
            THROW_EXCEPTION("Parameter '%s' is empty", "info");
        }

        Open(info->pwszContainerName, info->pwszProvName, info->dwProvType, info->dwFlags);
    }
    CATCH_EXCEPTION
}

void crypt::Key::Open(LPWSTR szContainer, LPWSTR szProvider, DWORD dwProvType, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Dispose();

        if (!CryptAcquireContextW(Ref(), szContainer, szProvider, dwProvType, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptAcquireContextW");
        }
    }
    CATCH_EXCEPTION;
}

void crypt::Key::GetParam(DWORD dwParam, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptGetProvParam(Get(), dwParam, pbData, pdwDataLen, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptGetProvParam");
        }
    }
    CATCH_EXCEPTION
}

void crypt::Key::SetParam(DWORD dwParam, PBYTE pbData, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptSetProvParam(Get(), dwParam, pbData, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptGetProvParam");
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> crypt::Key::GetBytes(DWORD dwParam)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> res(new Buffer(0));
        DWORD dwResLen = 0;

        GetParam(dwParam, NULL, &dwResLen);
        res->resize(dwResLen);
        GetParam(dwParam, res->data(), &dwResLen);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> crypt::Key::GetString(DWORD dwParam)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(dwParam);

        return Scoped<std::string>(new std::string((PCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

DWORD crypt::Key::GetNumber(DWORD dwParam)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        DWORD res = 0;
        DWORD dwResLen = sizeof(DWORD);

        GetParam(dwParam, (PBYTE)&res, &dwResLen);

        return res;
    }
    CATCH_EXCEPTION
}

void crypt::Key::SetBytes(DWORD dwParam, Scoped<Buffer> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, value->data());
    }
    CATCH_EXCEPTION
}

void crypt::Key::SetString(DWORD dwParam, Scoped<std::string> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, (PBYTE)value->c_str());
    }
    CATCH_EXCEPTION
}

void crypt::Key::SetNumber(DWORD dwParam, DWORD value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, (PBYTE)&value);
    }
    CATCH_EXCEPTION
}

Scoped<Key> crypt::Key::Copy(DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Key> key(new Key());

        if (!CryptDuplicateKey(Get(), NULL, 0, key->Ref())) {
            THROW_MSCAPI_EXCEPTION("CryptDuplicateKey");
        }

        return key;
    }
    CATCH_EXCEPTION
}
