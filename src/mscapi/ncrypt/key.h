#pragma once

#include "../../stdafx.h"
#include "../handle.h"

namespace ncrypt {

    class Key : public mscapi::Handle<NCRYPT_KEY_HANDLE> {
    public:
        Key() : Handle() {}
        Key(NCRYPT_KEY_HANDLE handle) : Handle(handle) {}

        void Dispose();
        void Open(PCRYPT_KEY_PROV_INFO info);
        void Open(
            _In_    LPCWSTR pszProvName,
            _In_    LPCWSTR pszKeyName,
            _In_opt_ DWORD  dwLegacyKeySpec,
            _In_    DWORD   dwFlags
        );

        /// <summary>Exports a CNG key to a memory BLOB</summary>
        /// <param name='pszBlobType'>
        /// <para>A null-terminated Unicode string that contains an identifier that specifies the type of BLOB to export</para>
        /// <para>BCRYPT_RSAPRIVATE_BLOB, BCRYPT_RSAPUBLIC_BLOB, BCRYPT_ECCPRIVATE_BLOB, BCRYPT_ECCPUBLIC_BLOB</para>
        /// </param>
        /// <param name='dwFlags'>Flags that modify function behavior. This can be zero or a combination of one or more values.</param>
        Scoped<Buffer> Export(LPCWSTR pszBlobType, DWORD dwFlags = 0);
        void Import(LPCWSTR pszBlobType, Scoped<Buffer> data, DWORD dwFlags = 0);

        void Delete(DWORD dwFlags = 0);
        void Finalize(DWORD dwFlags = 0);

        Scoped<Buffer> GetID();

        Scoped<Buffer> GetBytes(LPCWSTR pszProperty);
        Scoped<std::string> GetString(LPCWSTR pszProperty);
        Scoped<std::wstring> GetStringW(LPCWSTR pszProperty);
        DWORD GetNumber(LPCWSTR pszProperty);

        void SetBytes(LPCWSTR pszProperty, Scoped<Buffer> value, DWORD dwFlags = 0);
        void SetString(LPCWSTR pszProperty, Scoped<std::string> value, DWORD dwFlags = 0);
        void SetStringW(LPCWSTR pszProperty, Scoped<std::wstring> value, DWORD dwFlags = 0);
        void SetNumber(LPCWSTR pszProperty, DWORD value, DWORD dwFlags = 0);

        void GetParam(LPCWSTR pszProperty, PBYTE pbData, PDWORD pdwDataLen, DWORD dwFlags = 0);
        void SetParam(LPCWSTR pszProperty, PBYTE pbData, DWORD dwDataLen, DWORD dwFlags = 0);
    };

}