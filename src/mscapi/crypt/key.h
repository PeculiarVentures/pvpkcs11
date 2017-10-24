#pragma once

#include "../../stdafx.h"
#include "../handle.h"

namespace crypt {

    class Key : public mscapi::Handle<HCRYPTPROV>
    {
    public:
        Key() : Handle() {}
        Key(HCRYPTPROV handle) : Handle(handle) {}

        void Dispose();

        void Open(PCRYPT_KEY_PROV_INFO info);
        void Open(LPWSTR szContainer, LPWSTR szProvider, DWORD dwProvType, DWORD dwFlags);

        Scoped<Key> Copy(DWORD dwFlags = 0);

        Scoped<Buffer> GetBytes(DWORD dwParam);
        Scoped<std::string> GetString(DWORD dwParam);
        DWORD GetNumber(DWORD dwParam);

        void SetBytes(DWORD dwParam, Scoped<Buffer> value);
        void SetString(DWORD dwParam, Scoped<std::string> value);
        void SetNumber(DWORD dwParam, DWORD value);

    protected:
        void GetParam(DWORD dwParam, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags = 0);
        void SetParam(DWORD dwParam, PBYTE pbData, DWORD dwFlags = 0);
    };

}