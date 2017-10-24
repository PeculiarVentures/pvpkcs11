#pragma once

#include "../../stdafx.h"
#include "../handle.h"

namespace bcrypt {

    class Key : public mscapi::Handle<BCRYPT_KEY_HANDLE> {
    public:
        Key() : Handle() {}
        Key(BCRYPT_KEY_HANDLE handle) : Handle(handle) {}

        void Dispose();

        Scoped<Key> Duplicate();
        void ImportPublicKeyInfo(DWORD dwCertEncodingType, PCERT_PUBLIC_KEY_INFO pInfo, DWORD dwFlags = 0);
        Scoped<Buffer> Export(LPCWSTR pszBlobType, DWORD dwFlags = 0);

        Scoped<std::wstring> GetAlgorithmName();
        void ChangeMode(LPCWSTR pszMode);

        Scoped<Buffer> GetBytes(LPCWSTR pszProperty, DWORD dwFlags = 0);
        Scoped<std::string> GetString(LPCWSTR pszProperty, DWORD dwFlags = 0);
        Scoped<std::wstring> GetStringW(LPCWSTR pszProperty, DWORD dwFlags = 0);
        DWORD GetNumber(LPCWSTR pszProperty, DWORD dwFlags = 0);

        void SetBytes(LPCWSTR pszProperty, Scoped<Buffer> value, DWORD dwFlags = 0);
        void SetString(LPCWSTR pszProperty, Scoped<std::string> value, DWORD dwFlags = 0);
        void SetStringW(LPCWSTR pszProperty, Scoped<std::wstring> value, DWORD dwFlags = 0);
        void SetNumber(LPCWSTR pszProperty, DWORD value, DWORD dwFlags = 0);

    protected:
        void GetParam(LPCWSTR pszProperty, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags = 0);
        void SetParam(LPCWSTR pszProperty, PBYTE pbData, DWORD dwDataLen, DWORD dwFlags = 0);
    };

}