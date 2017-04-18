#include "crypto_sign.h"
#include "helper.h"
#include "../core/objects/public_key.h"

static CK_RV ProviderGetParam(HCRYPTPROV hProv, DWORD dwProp, LPWSTR pwsVal)
{
	BYTE* pbVal = NULL;
	DWORD dwValLen;
	if (!CryptGetProvParam(hProv, dwProp, pbVal, &dwValLen, 0)) {
		puts("ProviderGetParam");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	pbVal = (BYTE*)malloc(dwValLen);
	if (!CryptGetProvParam(hProv, dwProp, pbVal, &dwValLen, 0)) {
		puts("ProviderGetParam");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	std::mbstowcs(pwsVal, (char*)pbVal, dwValLen + 1);
	free(pbVal);
	return CKR_OK;
}

CryptoSign::CryptoSign()
{

}

CryptoSign::~CryptoSign()
{
	if (this->hProv) {
		CryptReleaseContext(this->hProv, 0);
		this->hProv = NULL;
	}
	if (this->hHash) {
		CryptDestroyHash(this->hHash);
		this->hHash = NULL;
	}
}

CK_RV CryptoSign::Init(
	HCRYPTPROV       prov,
	ALG_ID           algID,            /* the verification mechanism */
	HCRYPTKEY        hKey              /* signing key */
)
{
	this->hProv = prov;
	WCHAR provName[256];
	ProviderGetParam(prov, PP_NAME, provName);
	WCHAR containerName[256];
	ProviderGetParam(prov, PP_CONTAINER, containerName);
	DWORD dwProvType;
	DWORD dwProvTypeLen = sizeof(DWORD);
	if (!CryptGetProvParam(prov, PP_PROVTYPE, (BYTE*)&dwProvType, &dwProvTypeLen, 0)) {
		puts("CryptoSign::Init:CryptGetProvParam");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	fwprintf(stdout, L"Provider name %s\n", provName);
	fwprintf(stdout, L"Container name %s\n", containerName);
	fprintf(stdout, "Provider type %u\n", dwProvType);

	/*
	if (!CryptGetUserKey(prov, AT_KEYEXCHANGE, &this->hKey)) {
		puts("CryptoSign::Init:CryptGetUserKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	

	if (!CryptAcquireContext(&this->hProv, containerName, provName, dwProvType, 0)) {
		puts("CryptoSign::Init:CryptAcquireContext: Acquisition of context failed");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	*/

	if (!CryptCreateHash(this->hProv, algID, 0, 0, &this->hHash)) {
		puts("CryptoSign::Init:CryptCreateHash: Error during CryptBeginHash");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	this->hKey = hKey;
	return CKR_OK;
}

CK_RV CryptoSign::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	if (!CryptHashData(this->hHash, pPart, ulPartLen, 0)) {
		puts("CryptoSign::Update:CryptHashData");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV CryptoSign::Final(
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets the signature length */
)
{
	// Calculate signature
	if (!CryptSignHash(this->hHash, AT_SIGNATURE, NULL, 0, pSignature, pulSignatureLen)) {
		puts("CryptoSign::Final:CryptSignHash");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	if (pSignature) {
		// reverse data
		std::reverse(&pSignature[0], &pSignature[*pulSignatureLen]);
	}

	return CKR_OK;
}
