#pragma once

#include "../../stdafx.h"
#include "../handle.h"
#include "key.h"

namespace ncrypt {

    using NCryptKeyNameList = SList<NCryptKeyName>;

    class Provider : public mscapi::Handle<NCRYPT_PROV_HANDLE> {
    public:
        Provider() : Handle() {}
        Provider(NCRYPT_PROV_HANDLE handle) : Handle(handle) {}

        void Dispose();

        /// <summary>Loads and initializes a CNG key storage provider</summary>
        /// <param name='pszProvName'>
        /// <para>A  pointer to a null-terminated Unicode string that identifies the key storage provider to load</para>
        /// <para>MS_KEY_STORAGE_PROVIDER</para>
        /// <para>MS_SMART_CARD_KEY_STORAGE_PROVIDER</para>
        /// </param>
        void Open(LPCWSTR pszProvName, DWORD dwFlags = 0);

        /// <summery>Close a CNG key storage provider</summery>
        void Close();

        Scoped<Key> CreatePersistedKey(
            LPCWSTR pszAlgId,
            LPCWSTR pszKeyName,
            DWORD   dwLegacyKeySpec,
            DWORD   dwFlags
        );

        Scoped<Key> GetKey(LPCWSTR pszKeyName, DWORD dwLegacyKeySpec, DWORD dwFlags = 0);
        Scoped<Key> SetKey(
            Key*         key,
            LPCWSTR      pszBlobType,
            LPCWSTR      pszContainerName,
            bool         extractable
        );

        Scoped<NCryptKeyNameList> GetKeyNames(
            LPCWSTR pszScope = NULL,
            ULONG   dwFlags = 0
        );

        Scoped<std::wstring> GenerateRandomName();

        Scoped<std::string> GetProviderName();

    protected:
        std::wstring wstrProvName;
    };

}