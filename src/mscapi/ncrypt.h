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
		Object() {
            LOGGER_FUNCTION_BEGIN;
        }
		Object(T handle) : handle(handle) {
            LOGGER_FUNCTION_BEGIN;
        };

		void Set(T handle) {
            LOGGER_FUNCTION_BEGIN;

			this->handle = handle;
		}

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

		Scoped<std::string> GetBytes(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				Scoped<std::string> strData(new std::string(""));
				DWORD dwDataLen = sizeof(strData);

				GetParam(pszPropId, NULL, &dwDataLen);
				strData->resize(dwDataLen);
				GetParam(pszPropId, (BYTE*)strData->c_str(), &dwDataLen);

				return strData;
			}
			CATCH_EXCEPTION;
		}

		Scoped<std::wstring> GetBytesW(LPCWSTR pszPropId)
		{
            LOGGER_FUNCTION_BEGIN;

			try {
				auto data = GetBytes(pszPropId);

				return Scoped<std::wstring>(new std::wstring((wchar_t*)data->c_str()));
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
        Provider();
        Provider(
            NCRYPT_PROV_HANDLE handle
        );
		~Provider();

        static Scoped<std::wstring> GenerateRandomName();

		void Open(
			_In_opt_ LPCWSTR pszProviderName,
			_In_    DWORD   dwFlags
		);

		Scoped<Key> OpenKey(
			_In_    LPCWSTR pszKeyName,
			_In_opt_ DWORD  dwLegacyKeySpec,
			_In_    DWORD   dwFlags
		);

		Scoped<Key> TranslateHandle(
			_In_    HCRYPTPROV hLegacyProv,
			_In_opt_ HCRYPTKEY hLegacyKey,
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