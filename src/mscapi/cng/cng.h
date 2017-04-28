#pragma once

#include "../../stdafx.h"
#include "../../core/excep.h"
#include "../helper.h"

namespace cng {

	class Exception : public core::Pkcs11Exception {
	public:
		Exception(
			const char*        name,
			int                code,
			const char*        message,
			const char*        function,
			const char*        file,
			int                line
		) : Pkcs11Exception(name, code, message, function, file, line) {};
	};

#define NT_EXCEPTION_NAME "NTException"

#define THROW_NT_EXCEPTION(status)                                        \
	throw Scoped<core::Exception>(new cng::Exception(NT_EXCEPTION_NAME, status, GetNTErrorAsString(status).c_str(), __FUNCTION__, __FILE__, __LINE__))

	template<typename T>
	class IHandle {
	public:
		~IHandle()
		{
			Destroy();
		}

		T Get()
		{
			return handle;
		}

		virtual void Destroy() { };

	protected:
		T handle;

		void GetParam(LPCWSTR pszPropId, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags = 0)
		{
			DWORD status;
			if (!pbData) {
				status = BCryptGetProperty(handle, pszPropId, NULL, 0, pdwDataLen, dwFlags);
			}
			else {
				status = BCryptGetProperty(handle, pszPropId, pbData, *pdwDataLen, pdwDataLen, dwFlags);
			}
			if (status) {
				THROW_NT_EXCEPTION(status);
			}
		}
		DWORD GetNumber(LPCWSTR pszPropId)
		{
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
			try {
			auto data = GetBytes(pszPropId);

			return Scoped<std::wstring>(new std::wstring((wchar_t*)data->c_str()));
			}
			CATCH_EXCEPTION;
		}
	};

	class AlgorithmProvider : public IHandle<BCRYPT_ALG_HANDLE> {
	public:
		AlgorithmProvider(BCRYPT_ALG_HANDLE handle);

		static Scoped<AlgorithmProvider> Open(
			_In_        LPCWSTR pszAlgId,
			_In_opt_    LPCWSTR pszImplementation,
			_In_        ULONG   dwFlags
		);

		void Destroy();
	};

	class CryptoHash : public IHandle<BCRYPT_HASH_HANDLE> {
	public:
		static Scoped<CryptoHash> Create(LPCWSTR pszAlgId);
		void Update(PUCHAR pbData, DWORD dwDataLen);
		Scoped<std::string> Final();
		void Destroy();
		// Parameters
		DWORD GetLength();

	protected:
		Scoped<AlgorithmProvider> provider;
	};

	// CryptoKey

	class CryptoKey : public IHandle<BCRYPT_KEY_HANDLE> {
	public:
		CryptoKey(BCRYPT_KEY_HANDLE handle);
		void Destroy();

		Scoped<CryptoKey> Duplicate();

		// Properties
		Scoped<std::wstring> GetAlgorithmName();
	};

	// SymmetricKey

	class SymmetricKey : public CryptoKey {
	public:
		static Scoped<SymmetricKey> GenerateKey(Scoped<AlgorithmProvider> algorithm);

		SymmetricKey(BCRYPT_KEY_HANDLE handle) : CryptoKey(handle) {};
	};

	// AsymmetricKey

	class AsymmetricKey : public CryptoKey {
	public:
		static Scoped<AsymmetricKey> GenerateKeyPair(
			Scoped<AlgorithmProvider> algorithm,
			ULONG ulLength,
			ULONG ulFlags
		);

		AsymmetricKey(BCRYPT_KEY_HANDLE handle) : CryptoKey(handle) {};

		void Finalise();
	};

	class CryptoSign {
	public:
		~CryptoSign();

		static Scoped<CryptoSign> Create(
			LPCWSTR pszAlgId,
			Scoped<CryptoKey> key
		);

		void Update(PUCHAR pbData, ULONG ulDataLen);
		Scoped<std::string> Final(PVOID pvParams, ULONG ulFlags);

		void Destroy();

	protected:
		LPCWSTR pszAlgId;
		Scoped<CryptoKey> key;
		Scoped<CryptoHash> digest;

	};

}
