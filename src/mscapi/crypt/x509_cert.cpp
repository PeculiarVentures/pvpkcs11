#include "crypt.h"

using namespace crypt;

X509Certificate::X509Certificate()
{
	this->handle = NULL;
}

X509Certificate::X509Certificate(PCCERT_CONTEXT handle)
{
	this->handle = handle;
}

X509Certificate::~X509Certificate()
{
	this->Destroy();
}

void X509Certificate::Destroy()
{
	if (this->handle) {
		CertFreeCertificateContext(this->handle);
		this->handle = NULL;
	}
	PUBLIC_KEY_HASH = NULL;
	LABEL = NULL;
}

PCCERT_CONTEXT X509Certificate::Get()
{
	return this->handle;
}

void X509Certificate::Set(PCCERT_CONTEXT value)
{
	this->handle = value;
}

bool X509Certificate::HasPrivateKey()
{
	DWORD dwSize;
	return CertGetCertificateContextProperty(this->handle, CERT_KEY_PROV_INFO_PROP_ID, NULL, &dwSize);
}

Scoped<std::string> X509Certificate::GetHashPublicKey() {
	try {
		if (!PUBLIC_KEY_HASH.get()) {

			PUBLIC_KEY_HASH = 
                (
				this->handle->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				this->handle->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData
			);
		}
		return PUBLIC_KEY_HASH;
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> X509Certificate::GetLabel()
{
	try {
		if (!LABEL.get()) {
			WCHAR pszNameString[126];
			if (!CertGetNameStringW(this->handle, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (LPWSTR)pszNameString, 128)) {
				THROW_MSCAPI_ERROR();
			}
			char buf[256];
			WideCharToMultiByte(CP_UTF8, 0, pszNameString, -1, buf, 256, NULL, NULL);
			LABEL = Scoped<std::string>(new std::string(buf));
		}
		return LABEL;
	}
	CATCH_EXCEPTION;
}

Scoped<Key> X509Certificate::GetPublicKey()
{
	try {
		LPSTR pcPublicKeyAlgOID = this->handle->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId;
		DWORD dwProvType;
		if (strstr(pcPublicKeyAlgOID, szOID_PKCS_1)) {
			// RSA
			dwProvType = PROV_RSA_AES;
		}
		else {
			// EC
			dwProvType = PROV_EC_ECDSA_FULL;
		}

		Scoped<Provider> prov = Provider::Create(NULL, NULL, dwProvType, CRYPT_VERIFYCONTEXT);
		Scoped<Key> key = Key::Import(
			prov,
			X509_ASN_ENCODING,
			&handle->pCertInfo->SubjectPublicKeyInfo
		);

		return key;
	}
	CATCH_EXCEPTION;
}

void X509Certificate::GetParam(DWORD dwPropId, void* pvData, DWORD* pdwDataLen)
{
	try {
		if (!CertGetCertificateContextProperty(
			this->handle,
			dwPropId,
			pvData,
			pdwDataLen
		)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> X509Certificate::GetBufferParam(DWORD dwPropId)
{
	try {
		Scoped<std::string> result(new std::string());
		DWORD dwDataLen;
		this->GetParam(dwPropId, NULL, &dwDataLen);
		result->resize(dwDataLen);
		this->GetParam(dwPropId, (void*)result->c_str(), &dwDataLen);

		return result;
	}
	CATCH_EXCEPTION;
}

template<typename T>
Scoped<T> X509Certificate::GetStructureParam(DWORD dwPropId)
{
	try {
		DWORD dwDataLen;
		this->GetParam(dwPropId, NULL, &dwDataLen);
		Scoped<T>keyContext((T*)malloc(dwDataLen));
		this->GetParam(dwPropId, keyContext.get(), &dwDataLen);

		return keyContext;
	}
	CATCH_EXCEPTION;
}

Scoped<CERT_KEY_CONTEXT> X509Certificate::GetKeyContext()
{
	try {
		return this->GetStructureParam<CERT_KEY_CONTEXT>(CERT_KEY_CONTEXT_PROP_ID);
	}
	CATCH_EXCEPTION;
}

Scoped<CRYPT_KEY_PROV_INFO> X509Certificate::GetKeyProviderInfo()
{
	try {
		return this->GetStructureParam<CRYPT_KEY_PROV_INFO>(CERT_KEY_PROV_INFO_PROP_ID);
	}
	CATCH_EXCEPTION;
}

Scoped<Key> X509Certificate::GetPrivateKey()
{
	try {
		if (!HasPrivateKey()) {
			THROW_EXCEPTION("Certificated hasn't got Private key");
		}
		auto provInfo = this->GetKeyProviderInfo();
		Provider::CreateW(provInfo->pwszContainerName, provInfo->pwszProvName, provInfo->dwProvType, CRYPT_SILENT);
		Scoped<Provider> prov = Provider::CreateW(provInfo->pwszContainerName, provInfo->pwszProvName, provInfo->dwProvType, 0);
		Scoped<Key> privateKey(new Key(prov));
		return privateKey;
	}
	CATCH_EXCEPTION;
}