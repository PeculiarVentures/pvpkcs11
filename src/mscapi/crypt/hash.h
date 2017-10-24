#pragma once

#include "../../stdafx.h"
#include "../handle.h"
#include "key.h"

namespace crypt {

    class Hash : public mscapi::Handle<HCRYPTHASH> {
    public:
        Hash() : Handle() {};

        void Dispose();

        void Create(Key* key, ALG_ID algID, HCRYPTKEY hKey = NULL, DWORD dwFlags = 0);
        void Update(PBYTE pbData, DWORD dwDataLen, DWORD dwFlags = 0);

        Scoped<Buffer> GetBytes(DWORD dwParam, DWORD dwFlags = 0);
        Scoped<std::string> GetString(DWORD dwParam, DWORD dwFlags = 0);
        DWORD GetNumber(DWORD dwParam, DWORD dwFlags = 0);

        void SetBytes(DWORD dwParam, Scoped<Buffer> value, DWORD dwFlags = 0);
        void SetString(DWORD dwParam, Scoped<std::string> value, DWORD dwFlags = 0);
        void SetNumber(DWORD dwParam, DWORD value, DWORD dwFlags = 0);

    protected:
        void GetParam(DWORD dwParam, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags = 0);
        void SetParam(DWORD dwParam, PBYTE pbData, DWORD dwFlags = 0);

    };

}