#pragma once

#include "../../stdafx.h"
#include "../handle.h"
#include "key.h"

namespace bcrypt {

    class Provider : public mscapi::Handle<BCRYPT_ALG_HANDLE> {
    public:
        static Scoped<Buffer> GenerateRandom(DWORD dwOutLen);
        static Scoped<Provider> Create(LPCWSTR pszAlgId, LPCWSTR pszImplementation = NULL, DWORD dwFlags = 0);

        Provider() : Handle() {}
        Provider(BCRYPT_ALG_HANDLE handle) : Handle(handle) {}

        void Dispose();

        void Open(LPCWSTR pszAlgId, LPCWSTR pszImplementation, DWORD dwFlags = 0);
        void Close(DWORD dwFlags = 0);

        /// <summary>Generates symmetric key</summary>
        Scoped<bcrypt::Key> GenerateKey(
            PUCHAR  pbKeyObject,
            ULONG   cbKeyObject,
            PUCHAR  pbSecret,
            ULONG   cbSecret,
            ULONG   dwFlags
        );

        Scoped<Key> ImportKey(
            LPCWSTR pszBlobType,
            PBYTE   pbData,
            DWORD   cbData,
            DWORD   dwFlags
        );

    };

}