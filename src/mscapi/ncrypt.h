#pragma once

#include "../stdafx.h"

#include <ncrypt.h>
#include "helper.h"

namespace ncrypt {

    typedef std::vector<Scoped<NCryptKeyName>> NCryptKeyNames;
    typedef std::vector<Scoped<NCryptProviderName>> NCryptProviderNames;

	template<typename T>
	class Object {
	public:
		Object(): handle(NULL) {
            LOGGER_FUNCTION_BEGIN;
        }
		Object(T handle) : handle(handle) {
            LOGGER_FUNCTION_BEGIN;
        };

		void Set(T handle) {
            LOGGER_FUNCTION_BEGIN;

			this->handle = handle;
		}

        /*T* operator & () {
            return &handle;
        }*/

		T Get() {
            LOGGER_FUNCTION_BEGIN;

			return handle;
		}

		void GetParam(LPCWSTR pszPropId, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags = 0)
		{
            LOGGER_FUNCTION_BEGIN;

			NTSTATUS status;
			if (!pbData) {
				status = NCryptGetProperty(handle, pszPropId, NULL, 0, pdwDataLen, dwFlags);
			}
			else {
				status = NCryptGetProperty(handle, pszPropId, pbData, *pdwDataLen, pdwDataLen, dwFlags);
			}
			if (status) {
				THROW_NT_EXCEPTION(status);
			}
		}

		DWORD GetNumber(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				DWORD dwData;
				DWORD dwDataLen = sizeof(dwData);

				GetParam(pszPropId, (BYTE*)&dwData, &dwDataLen);

				return dwData;
			}
			CATCH_EXCEPTION;
		}

		bool GetBoolean(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				bool bData;
				DWORD dwDataLen = sizeof(bData);

				GetParam(pszPropId, (BYTE*)&bData, &dwDataLen);

				return bData;
			}
			CATCH_EXCEPTION;
		}

        Scoped<Buffer> GetBytes(LPCWSTR pszPropId)
        {
            LOGGER_FUNCTION_BEGIN;

            try {
                Scoped<Buffer> buffer(new Buffer(0));
                DWORD dwDataLen = 0;

                GetParam(pszPropId, NULL, &dwDataLen);
                buffer->resize(dwDataLen);
                GetParam(pszPropId, buffer->data(), &dwDataLen);

                return buffer;
            }
            CATCH_EXCEPTION;
        }

		Scoped<std::string> GetString(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				Scoped<std::string> result(new std::string(""));
				DWORD dwDataLen = 0;

				GetParam(pszPropId, NULL, &dwDataLen);
                result->resize(dwDataLen);
				GetParam(pszPropId, result->data(), &dwDataLen);

				return result;
			}
			CATCH_EXCEPTION;
		}

		Scoped<std::wstring> GetStringW(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				auto data = GetBytes(pszPropId);

				return Scoped<std::wstring>(new std::wstring((wchar_t*)data->data()));
			}
			CATCH_EXCEPTION;
		}

		void SetParam(
			_In_                    LPCWSTR pszProperty,
			_In_reads_bytes_(cbInput)    PUCHAR   pbInput,
			_In_                    ULONG   cbInput,
			_In_                    ULONG   dwFlags = 0
		)
		{
            LOGGER_FUNCTION_BEGIN;

			NTSTATUS status = NCryptSetProperty(
				handle,
				pszProperty,
				pbInput,
				cbInput,
				dwFlags
			);
			if (status) {
				THROW_NT_EXCEPTION(status);
			}
		}

		void SetNumber(
			LPCWSTR pszProperty,
			ULONG   ulValue,
			ULONG   dwFlags = 0
		)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				SetParam(
					pszProperty,
					(PUCHAR)&ulValue,
					sizeof(ulValue),
					dwFlags
				);
			}
			CATCH_EXCEPTION;
		}

		void SetBoolean(
			LPCWSTR pszProperty,
			bool    bbValue,
			ULONG   dwFlags = 0
		)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				SetParam(
					pszProperty,
					(PUCHAR)&bbValue,
					sizeof(bbValue),
					dwFlags
				);
			}
			CATCH_EXCEPTION;
		}

	protected:
		T handle;
	};

	class Provider;
	class Key;

	class Key : public Object<NCRYPT_KEY_HANDLE> {
	public:
		Key(
			NCRYPT_KEY_HANDLE handle
		);
		~Key();

		void Finalize(
			ULONG dwFlags = 0
		);

        Scoped<Buffer> ExportKey(
            _In_    LPCWSTR pszBlobType,
            _In_    DWORD   dwFlags
        );
        
        void Delete(
            ULONG           dwFlags
        );
        Scoped<CERT_PUBLIC_KEY_INFO> GetPublicKeyInfo();
        Scoped<Buffer> GetId();
	};

	class Provider : public Object<NCRYPT_PROV_HANDLE> {
	public:
        /// <summary>Translates a CryptoAPI handle into a CNG key handle</summary>
        /// <param name='hLegacyProv'>The handle of the CryptoAPI provider that contains the key to translate. This function will translate the CryptoAPI key that is in the container in this provider.</param>
        /// <param name='hLegacyKey'>
        /// <para>The handle of a CryptoAPI key to use to help determine the key specification for the returned key. This parameter is ignored if the dwLegacyKeySpec parameter contains a value other than zero.</para>
        /// <para>If hLegacyKey is NULL and dwLegacyKeySpec is zero, this function will attempt to determine the key specification from the hLegacyProv handle.</para>
        /// </param>
        /// <param name='dwLegacyKeySpec'>
        /// <para>Specifies the key specification for the key. This can be one of the following values.</para>
        /// <para>0 -The key is none of the types below.</para>
        /// <para>AT_KEYEXCHANGE(1) - The key is a key exchange key.</para>
        /// <para>AT_SIGNATURE(2) - The key is a signature key.</para>
        /// <para>If hLegacyKey is NULL and dwLegacyKeySpec is zero, this function will attempt to determine the key specification from the hLegacyProv handle.</para>
        /// </param>
        /// <param name='dwFlags'>A set of flags that modify the behavior of this function. No flags are defined for this function.</param>
        static Scoped<Key> TranslateHandle(
            _In_        HCRYPTPROV  hLegacyProv,
            _In_opt_    HCRYPTKEY   hLegacyKey,
            _In_opt_    DWORD       dwLegacyKeySpec,
            _In_        DWORD       dwFlags
        );

        Provider();
        Provider(
            NCRYPT_PROV_HANDLE handle
        );
		~Provider();

        static Scoped<std::wstring> GenerateRandomName();

        /// <summary>Opens new provider</summary>
        /// <param name='pszProviderName'>
        /// <para>
        /// A pointer to a null-terminated Unicode string that identifies the key storage provider to load. 
        /// This is the registered alias of the key storage provider. This parameter is optional and can be NULL. If this parameter is NULL, the default key storage provider is loaded. The following values identify the built-in key storage providers.
        /// </para>
        /// <para>MS_KEY_STORAGE_PROVIDER</para>
        /// <para>MS_SMART_CARD_KEY_STORAGE_PROVIDER</para>
        /// </param>
        /// <param name='dwFlags'>Flags that modify the behavior of the function. No flags are defined for this function.</param>
		void Open(
			_In_opt_    LPCWSTR     pszProviderName,
			_In_        DWORD       dwFlags
		);

		Scoped<Key> OpenKey(
			_In_    LPCWSTR pszKeyName,
			_In_opt_ DWORD  dwLegacyKeySpec,
			_In_    DWORD   dwFlags
		);

		Scoped<Key> CreatePersistedKey(
			_In_    LPCWSTR pszAlgId,
			_In_opt_ LPCWSTR pszKeyName,
			_In_    DWORD   dwLegacyKeySpec,
			_In_    DWORD   dwFlags
		);

        Scoped<Key> ImportKey(
            _In_        LPCWSTR             pszBlobType,
            _In_reads_bytes_(cbData) PBYTE  pbData,
            _In_        DWORD               cbData,
            _In_        DWORD               dwFlags
        );

        Scoped<NCryptKeyNames> GetKeyNames(
            ULONG               dwFlags
        );

	};

    /*
    Copy key to new provider
    key - original key
    pszBlobType - type of key blob
    provider - provider for key
    pszContainerName - name for container. If key is NULL, then key will be in memory
     */
    Scoped<Key> CopyKeyToProvider(
        Key*                key,
        LPCWSTR             pszBlobType,
        Provider*           provider,
        LPCWSTR             pszContainerName,
        bool                extractable
    );

}