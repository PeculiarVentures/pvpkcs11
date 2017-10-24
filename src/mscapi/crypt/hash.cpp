#include "hash.h"

#include "../helper.h"

void crypt::Hash::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            CryptDestroyHash(Get());
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

void crypt::Hash::Create(Key* key, ALG_ID algID, HCRYPTKEY hKey, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptCreateHash(key->Get(), algID, NULL, dwFlags, Ref())) {
            THROW_MSCAPI_EXCEPTION("CryptCreateHash");
        }
    }
    CATCH_EXCEPTION
}

void crypt::Hash::Update(PBYTE pbData, DWORD dwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptHashData(Get(), pbData, dwDataLen, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptHashData");
        }
    }
    CATCH_EXCEPTION
}

void crypt::Hash::GetParam(DWORD dwParam, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptGetHashParam(Get(), dwParam, pbData, pdwDataLen, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptGetProvParam");
        }
    }
    CATCH_EXCEPTION
}

void crypt::Hash::SetParam(DWORD dwParam, PBYTE pbData, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CryptSetHashParam(Get(), dwParam, pbData, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptGetProvParam");
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> crypt::Hash::GetBytes(DWORD dwParam, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> res(new Buffer(0));
        DWORD dwResLen = 0;

        GetParam(dwParam, NULL, &dwResLen, dwFlags);
        res->resize(dwResLen);
        GetParam(dwParam, res->data(), &dwResLen, dwFlags);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> crypt::Hash::GetString(DWORD dwParam, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf = GetBytes(dwParam, dwFlags);

        return Scoped<std::string>(new std::string((PCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

DWORD crypt::Hash::GetNumber(DWORD dwParam, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        DWORD res = 0;
        DWORD dwResLen = sizeof(DWORD);

        GetParam(dwParam, (PBYTE)&res, &dwResLen, dwFlags);

        return res;
    }
    CATCH_EXCEPTION
}

void crypt::Hash::SetBytes(DWORD dwParam, Scoped<Buffer> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, value->data(), dwFlags);
    }
    CATCH_EXCEPTION
}

void crypt::Hash::SetString(DWORD dwParam, Scoped<std::string> value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, (PBYTE)value->c_str(), dwFlags);
    }
    CATCH_EXCEPTION
}

void crypt::Hash::SetNumber(DWORD dwParam, DWORD value, DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetParam(dwParam, (PBYTE)&value, dwFlags);
    }
    CATCH_EXCEPTION
}