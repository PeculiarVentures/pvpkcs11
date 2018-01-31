#pragma once

#include "../../stdafx.h"
#include "../handle.h"
#include "../crypto_key.h"

namespace crypt {

    class Certificate : public mscapi::Handle<PCCERT_CONTEXT> {
    public:
        Certificate() : Handle() {}
        Certificate(PCCERT_CONTEXT handle) : Handle(handle) {}

        void Dispose();

        void Import(PUCHAR pbData, DWORD dwDataLen);
        Scoped<Buffer> Export();
        Scoped<Certificate> Duplicate();
        void DeleteFromStore();

        BOOL HasPrivateKey();

        Scoped<Buffer> GetID();

        Scoped<mscapi::CryptoKey> GetPublicKey();
        Scoped<mscapi::CryptoKey> GetPrivateKey();
        Scoped<ProviderInfo> GetProviderInfo();

        Scoped<std::string> GetName();

        BOOL HasProperty(DWORD dwPropId);
        Scoped<Buffer> GetBytes(DWORD dwPropId);
        Scoped<std::string> GetString(DWORD dwPropId);
        DWORD GetNumber(DWORD dwPropId);
        Scoped<std::wstring> GetStringW(DWORD dwPropId);

        void SetBytes(DWORD dwPropId, Scoped<Buffer> value);
        void SetString(DWORD dwPropId, Scoped<std::string> value);
        void SetStringW(DWORD dwPropId, Scoped<std::wstring> value);

    protected:
        void GetProperty(DWORD dwPropId, PBYTE pbData, PDWORD pdwDataLen);
        void SetProperty(DWORD dwPropId, PBYTE pbData, DWORD dwFlag = 0);
    };

}