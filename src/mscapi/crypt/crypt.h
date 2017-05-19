#pragma once

#include "../../stdafx.h"
#include "../../core/collection.h"
#include "../../core/excep.h"

#include "../certificate.h"

namespace crypt {

	/**
	 * Exception
	 */

	class Exception : public core::Pkcs11Exception {
	public:
		Exception(
			const char*        name,
			int                code,
			const char*        message,
			const char*        function,
			const char*        file,
			int                line
		);
	};

	/**
	 * Provider
	 */

	class Provider {

	public:
		static Scoped<Provider> Create(
			LPCSTR    szContainer,
			LPCSTR    szProvider,
			DWORD     dwProvType,
			DWORD     dwFlags
		);
		static Scoped<Provider> CreateW(
			LPWSTR    szContainer,
			LPWSTR    szProvider,
			DWORD     dwProvType,
			DWORD     dwFlags
		);

		Provider();
		Provider(HCRYPTPROV);
		~Provider();

		void AcquireContext(
			LPCSTR    szContainer,
			LPCSTR    szProvider,
			DWORD     dwProvType,
			DWORD     dwFlags
		);
		void AcquireContextW(
			LPWSTR    szContainer,
			LPWSTR    szProvider,
			DWORD     dwProvType,
			DWORD     dwFlags
		);
		void Destroy();
		void Destroy(DWORD dwFlags);

		HCRYPTPROV Get();
		void Set(HCRYPTPROV handle);

		// Properties
		Scoped<std::string> GetContainer();
		Scoped<std::string> GetName();
		DWORD GetType();
		DWORD GetKeySpec();
		Scoped<Collection<Scoped<std::string>>> GetContainers();

	protected:
		HCRYPTPROV handle;

		void GetParam(
			DWORD   dwParam,
			BYTE    *pbData,
			DWORD   *pdwDataLen,
			DWORD   dwFlags
		);
		Scoped<std::string> GetBufferParam(
			DWORD   dwParam,
			DWORD   dwFlag = 0
		);
		DWORD GetNumberParam(
			DWORD   dwParam
		);

	};

	class Key {
	public:
		static Scoped<Key> Generate(
			Scoped<Provider>  prov,
			ALG_ID            uiAlgId,
			DWORD             dwFlags
		) throw(Exception);
		static Scoped<Key> Import(
			Scoped<Provider>  prov,
			BYTE              *pbData,
			DWORD             dwDataLen,
			DWORD             dwFlags
		) throw(Exception);
		static Scoped<Key> Import(
			Scoped<Provider>       prov,
			DWORD                  dwCertEncodingType,
			PCERT_PUBLIC_KEY_INFO  pInfo
		) throw(Exception);

		Key();
		Key(Scoped<Provider> prov);
		Key(HCRYPTKEY handle);
		~Key();

		Scoped<Key> Copy() throw(Exception);
		void Destroy();

		HCRYPTKEY Get() throw(Exception);
		void Set(HCRYPTKEY value);

		Scoped<Provider>  GetProvider();
		DWORD GetKeyLen();
		DWORD GetBlockLen();
		ALG_ID GetAlgId();
		DWORD GetMode();
		DWORD GetPadding();

		void SetIV(BYTE* pbData, DWORD pbDataLen);
		void SetPadding(DWORD dwPadding);

	protected:
		HCRYPTKEY         handle;
		Scoped<Provider>  prov;
	};

    /*
	class X509Certificate {

	public:
		X509Certificate();
		X509Certificate(PCCERT_CONTEXT handle);
		~X509Certificate();

		void Destroy();

		Scoped<std::string> GetHashPublicKey();
		bool HasPrivateKey();
		Scoped<Key> GetPrivateKey();
		Scoped<Key> GetPublicKey();

		PCCERT_CONTEXT Get();
		void Set(PCCERT_CONTEXT value);

		Scoped<std::string> GetLabel();
		Scoped<CERT_KEY_CONTEXT> GetKeyContext();
		Scoped<CRYPT_KEY_PROV_INFO> GetKeyProviderInfo();

	protected:
		PCCERT_CONTEXT handle;

		void GetParam(DWORD dwPropId, void* pvData, DWORD* pdwDataLen);
		Scoped<std::string> GetBufferParam(DWORD dwPropId);
		template<typename T>
		Scoped<T> GetStructureParam(DWORD dwPropId);

		// Cache
		Scoped<std::string> PUBLIC_KEY_HASH;
		Scoped<std::string> LABEL;
	};
    */

	class CertStore {
	public:
		CertStore();
		~CertStore();

		std::vector<Scoped<mscapi::X509Certificate>> GetCertificates();

		void Open(LPCSTR storeName);
		void Close();
	protected:
		bool opened;
		HCERTSTORE hStore;
		LPCSTR name;
	};

}

#define MSCAPI_EXCEPTION_NAME "MSCAPIException"

#define THROW_MSCAPI_CODE_ERROR(dwErrorCode)                        \
	throw Scoped<core::Exception>(new crypt::Exception(MSCAPI_EXCEPTION_NAME, dwErrorCode, "", __FUNCTION__, __FILE__, __LINE__)); \

#define THROW_MSCAPI_ERROR()                                        \
	{                                                               \
		DWORD dwErrorCode = GetLastError();							\
		THROW_MSCAPI_CODE_ERROR(dwErrorCode); \
	}