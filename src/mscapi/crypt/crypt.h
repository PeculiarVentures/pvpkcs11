#pragma once

#include "../../stdafx.h"
#include "../../core/collection.h"

namespace crypt {

	/**
	 * Exception
	 */

	class Exception : public std::exception {
	public:
		const char* functionName;
		const char* codeLine;
		const DWORD code;
		Scoped<std::string> message;

		Exception(const DWORD code, const char* funcName);

		virtual char const* what() const;
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
		);
		static Scoped<Key> Import(
			Scoped<Provider>  prov,
			BYTE              *pbData,
			DWORD             dwDataLen,
			DWORD             dwFlags
		);
		static Scoped<Key> Import(
			Scoped<Provider>       prov,
			DWORD                  dwCertEncodingType,
			PCERT_PUBLIC_KEY_INFO  pInfo
		);

		Key();
		Key(Scoped<Provider> prov);
		Key(HCRYPTKEY handle);
		~Key();

		Scoped<Key> Copy();
		void Destroy();

		HCRYPTKEY Get();
		void Set(HCRYPTKEY value);

		Scoped<Provider>  getProvider();

	protected:
		HCRYPTKEY         handle;
		Scoped<Provider>  prov;
	};

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

	class CertStore {
	public:
		CertStore();
		~CertStore();

		Scoped<Collection<Scoped<X509Certificate>>> GetCertificates();

		void Open(LPCSTR storeName);
		void Close();
	protected:
		bool opened;
		HCERTSTORE hStore;
		LPCSTR name;
	};

	class Hash {
	public:
		static Scoped<Hash> Create(
			Scoped<Provider>  prov,
			ALG_ID            algId,
			Scoped<Key>       key,
			DWORD             dwFlag
		);

		static Scoped<std::string> Once(
			DWORD    provType,
			ALG_ID   algId, 
			BYTE*    pbData, 
			DWORD    dwDataLen
		);

		Hash(
			Scoped<Provider>  prov,
			ALG_ID            algId,
			Scoped<Key>       key,
			DWORD             dwFlag
		);

		void Update(
			BYTE* pbData,
			DWORD dwDataLen
		);

		HCRYPTHASH Get();

		DWORD GetSize();
		DWORD GetAlgId();
		Scoped<std::string> GetValue();

	protected:
		Scoped<Provider>  prov;
		Scoped<Key>       key;
		HCRYPTHASH        handle;

		void GetParam(DWORD dwPropId, BYTE* pvData, DWORD* pdwDataLen);
		DWORD GetNumber(DWORD dwPropId);
	};

	class Sign {
	public:
		static Scoped<Sign> Create(
			ALG_ID            algId,
			Scoped<Key>       key
		);

		static Scoped<std::string> Once(
			ALG_ID        algId,
			Scoped<Key>   key,
			BYTE*         pbData,
			DWORD         dwDataLen
		);

		Sign(
			ALG_ID            algId,
			Scoped<Key>       key
		);

		void Update(
			BYTE* pbData,
			DWORD dwDataLen
		);

		Scoped<std::string> Final();

	protected:
		Scoped<Key>       key;
		Scoped<Hash>      hash;

	};

	class Verify {
	public:
		static Scoped<Verify> Create(
			ALG_ID            algId,
			Scoped<Key>       key
		);

		static bool Once(
			ALG_ID        algId,
			Scoped<Key>   key,
			BYTE*         pbData,
			DWORD         dwDataLen,
			BYTE*         pbSignature,
			DWORD         dwSignatureLen
		);

		Verify(
			ALG_ID            algId,
			Scoped<Key>       key
		);

		void Update(
			BYTE*  pbData,
			DWORD  dwDataLen
		);

		bool Final(
			BYTE*  pbSignature,
			DWORD  dwSignatureLen
		);

	protected:
		Scoped<Key>       key;
		Scoped<Hash>      hash;

	};

}

#define THROW_MS_ERROR()                                            \
	fprintf(stdout, "NativeError: %s:%d\n", __FILE__, __LINE__);    \
    throw crypt::Exception(GetLastError(), __FUNCTION__);

#define DIGEST_SHA1(pbData, dwDataLen)                              \
	crypt::Hash::Once(PROV_RSA_AES, CALG_SHA1, pbData, dwDataLen)
#define DIGEST_SHA256(pbData, dwDataLen)                            \
	crypt::Hash::Once(PROV_RSA_AES, CALG_SHA_256, pbData, dwDataLen)
#define DIGEST_SHA384(pbData, dwDataLen)                            \
	crypt::Hash::Once(PROV_RSA_AES, CALG_SHA_384, pbData, dwDataLen)
#define DIGEST_SHA512(pbData, dwDataLen)                            \
	crypt::Hash::Once(PROV_RSA_AES, CALG_SHA_512, pbData, dwDataLen)