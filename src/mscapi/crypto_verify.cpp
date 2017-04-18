#include "crypto_verify.h"
#include "../core/objects/public_key.h"
#include "helper.h"

CryptoVerify::CryptoVerify()
{

}

CryptoVerify::~CryptoVerify()
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

CK_RV CryptoVerify::Init(
	HCRYPTPROV prov,         /* type of provider */
	ALG_ID     algID,            /* the verification mechanism */
	HCRYPTKEY  hKey              /* verification key */
)
{
	/*
	if (!CryptAcquireContext(&this->hProv, NULL, NULL, provType, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		printf("Acquisition of context failed.\n");
		return CKR_FUNCTION_FAILED;
	}
	*/

	if (!CryptCreateHash(prov, algID, 0, 0, &this->hHash)) {
		printf("Error during CryptBeginHash!\n");
		return CKR_FUNCTION_FAILED;
	}

	this->hKey = hKey;
	return CKR_OK;
}

CK_RV CryptoVerify::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	if (!CryptHashData(this->hHash, pPart, ulPartLen, 0)) {
		puts("CryptoVerify::Update:CryptHashData");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV CryptoVerify::Final(
	CK_BYTE_PTR       pSignature,     /* signature to verify */
	CK_ULONG          ulSignatureLen  /* signature length */
)
{
	if (pSignature) {
		// reverse data
		std::reverse(&pSignature[0], &pSignature[ulSignatureLen]);
	}

	// Verify signature
	if (!CryptVerifySignature(this->hHash, pSignature, ulSignatureLen, this->hKey, NULL, 0)) {
		DWORD dwLastError = GetLastError();
		if (dwLastError == NTE_BAD_SIGNATURE) {
			return CKR_SIGNATURE_INVALID;
		}
		puts("CryptoVerify::Final:CryptVerifySignature");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}