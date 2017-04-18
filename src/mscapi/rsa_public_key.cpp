#include "rsa_public_key.h"
#include "helper.h"

MscapiRsaPublicKey::~MscapiRsaPublicKey()
{
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetToken)
{
	return this->GetBool(pValue, pulValueLen, this->token);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetPrivate)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetModifiable)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetLabel)
{
	char *label = "RSA public key";
	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)label, strlen(label));
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetCopyable)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetID)
{
	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)this->id.c_str(), this->id.length());
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetStartDate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetEndDate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetDerive)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetLocal)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetKeyGenMechanism)
{
	return this->GetNumber(pValue, pulValueLen, CKM_RSA_PKCS);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetAllowedMechanisms)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetSubject)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetEncrypt)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetVerify)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetVerifyRecover)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetWrap)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetTrusted)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetWrapTemplate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetModulus)
{
	DWORD dwPublicKeyLen = 0;
	BYTE* pbPublicKey = NULL;

	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	PUBLICKEYSTRUC* header = (PUBLICKEYSTRUC*)pbPublicKey;
	RSAPUBKEY* info = (RSAPUBKEY*)(pbPublicKey + sizeof(PUBLICKEYSTRUC));
	BYTE* modulus = (BYTE*)(pbPublicKey + sizeof(PUBLICKEYSTRUC) + sizeof(RSAPUBKEY));

	// reverse bytes
	std::reverse(&modulus[0], &modulus[info->bitlen / 8]);

	CK_RV rv = this->GetBytes(pValue, pulValueLen, modulus, info->bitlen / 8);

	free(pbPublicKey);

	return rv;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetModulusBits)
{
	DWORD dwPublicKeyLen = 0;
	BYTE* pbPublicKey = NULL;

	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	PUBLICKEYSTRUC* header = (PUBLICKEYSTRUC*)pbPublicKey;
	RSAPUBKEY* info = (RSAPUBKEY*)(pbPublicKey + sizeof(PUBLICKEYSTRUC));

	CK_RV rv = this->GetNumber(pValue, pulValueLen, info->bitlen);

	free(pbPublicKey);

	return rv;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetPublicExponent)
{
	DWORD dwPublicKeyLen = 0;
	BYTE* pbPublicKey = NULL;

	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}
	pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
	if (!CryptExportKey(this->key->handle, NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
		puts("MscapiRsaPublicKey::GetModulus:CryptExportKey");
		PRINT_WIN_ERROR();
		return CKR_FUNCTION_FAILED;
	}

	PUBLICKEYSTRUC* header = (PUBLICKEYSTRUC*)pbPublicKey;
	RSAPUBKEY* info = (RSAPUBKEY*)(pbPublicKey + sizeof(PUBLICKEYSTRUC));

	CK_BYTE_PTR pbPublicExponent;
	if (info->pubexp == 2) {
		pbPublicExponent = (CK_BYTE_PTR)malloc(1);
		pbPublicExponent[0] = 3;
	}
	else {
		pbPublicExponent = (CK_BYTE_PTR)malloc(3);
		pbPublicExponent[0] = 1;
		pbPublicExponent[1] = 0;
		pbPublicExponent[2] = 1;
	}
	CK_RV rv = this->GetBytes(pValue, pulValueLen, pbPublicExponent, info->pubexp == 3 ? 1 : 3);

	free(pbPublicKey);
	free(pbPublicExponent);

	return rv;
}
