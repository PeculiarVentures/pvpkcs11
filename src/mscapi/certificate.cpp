#include "certificate.h"
#include "cert_store.h"

static CK_RV CryptCreateHashSha1(CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG ulDigestLen)
{
	CHECK_ARGUMENT_NULL(pData);
	CHECK_ARGUMENT_NULL(pDigest);

	HCRYPTPROV hCryptProv;
	HCRYPTHASH hHash;

	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
		printf("Error during CryptAcquireContext\n");
		goto err;
	}

	if (!CryptCreateHash(hCryptProv, CALG_SHA1, 0, 0, &hHash)) {
		printf("Error during CryptCreateHash\n");
		goto err;
	}

	if (!CryptHashData(hHash, (BYTE*)pData, (DWORD)ulDataLen, 0)) {
		printf("Error during CryptHashData.\n");
		goto err;
	}

	DWORD dwDigestLen;
	if (!CryptGetHashParam(hHash, HP_HASHVAL, pDigest, &dwDigestLen, 0)) {
		puts("Error during CryptGetHashParam\n");
		goto err;
	}

	return CKR_OK;

	if (hHash)
		CryptDestroyHash(hHash);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);

err:
	if (hHash)
		CryptDestroyHash(hHash);
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);

	return CKR_FUNCTION_FAILED;
}

MscapiCertificate::MscapiCertificate(PCCERT_CONTEXT cert) : MscapiCertificate(cert, false)
{
}

MscapiCertificate::MscapiCertificate(PCCERT_CONTEXT cert, CK_BBOOL trusted)
{
	this->cert = cert;
	this->trusted = trusted;
	this->handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
}

MscapiCertificate::~MscapiCertificate()
{
	if (this->cert) {
		CertFreeCertificateContext(this->cert);
		this->cert = NULL;
	}
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetLabel)
{
	WCHAR pszNameString[128];
	if (CertGetNameString(this->cert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, (LPSTR)pszNameString, 128)) {
		char buf[256];
		WideCharToMultiByte(CP_UTF8, 0, pszNameString, -1, buf, 256, NULL, NULL);
		size_t convertedLen = strlen(buf);
		if (pValue) {
			if (*pulValueLen < convertedLen) {
				return CKR_BUFFER_TOO_SMALL;
			}
			memcpy(pValue, buf, convertedLen);
		}
		*pulValueLen = convertedLen;
	}
	else {
		printf("Error on CertGetNameString\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSerialNumber)
{
	return this->GetBytes(pValue, pulValueLen, this->cert->pCertInfo->SerialNumber.pbData, this->cert->pCertInfo->SerialNumber.cbData);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetValue)
{
	return this->GetBytes(pValue, pulValueLen, this->cert->pbCertEncoded, this->cert->cbCertEncoded);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSubject)
{
	return this->GetBytes(pValue, pulValueLen, this->cert->pCertInfo->Subject.pbData, this->cert->pCertInfo->Subject.cbData);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetIssuer)
{
	return this->GetBytes(pValue, pulValueLen, this->cert->pCertInfo->Issuer.pbData, this->cert->pCertInfo->Issuer.cbData);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetToken)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetModifiable)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetTrusted)
{
	return this->GetBool(pValue, pulValueLen, this->trusted);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetCheckValue)
{
	CK_BYTE buf[64];
	CK_ULONG bufLen;
	if (!CertGetCertificateContextProperty(this->cert, CERT_HASH_PROP_ID, buf, &bufLen)) {
		return CKR_FUNCTION_FAILED;
	}
	if (pValue) {
		return this->GetBytes(pValue, pulValueLen, buf, CERTIFICATE_CHECK_VALUE_LENGTH);
	}
	*pulValueLen = CERTIFICATE_CHECK_VALUE_LENGTH;
	return CKR_OK;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetID)
{
	return this->GetHashOfSubjectPublicKey(pValue, pulValueLen);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfSubjectPublicKey)
{
	if (pValue) {
		if (*pulValueLen < 20) {
			return CKR_BUFFER_TOO_SMALL;
		}
		return CryptCreateHashSha1(
			this->cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
			this->cert->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
			pValue, *pulValueLen);
	}
	
	*pulValueLen = 20;
	
	return CKR_OK;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfIssuerPublicKey)
{	
	HCERTSTORE hStore = CertOpenSystemStore(NULL, "root");
	if (!hStore) {
		puts("Error: CertOpenSystemStore");
	}

	DWORD dwFlags = 0;
	PCCERT_CONTEXT certIssuer = CertGetIssuerCertificateFromStore(hStore, this->cert, NULL, &dwFlags);
	// TODO: Clear cert context
	printf("CertGetIssuerCertificateFromStore:Flag: %u\n", dwFlags);
	if (certIssuer) {
		if (pValue) {
			if (*pulValueLen < 20) {
				return CKR_BUFFER_TOO_SMALL;
			}

			return CryptCreateHashSha1(
				certIssuer->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData,
				certIssuer->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData,
				pValue, *pulValueLen);
		}

		*pulValueLen = 20;
	}
	else {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}

	if (!CertCloseStore(hStore, 0)) {
		puts("Error: CertCloseStore");
	}

	return CKR_OK;
}
