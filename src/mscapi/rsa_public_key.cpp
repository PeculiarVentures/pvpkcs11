#include "rsa_public_key.h"
#include "helper.h"

MscapiRsaPublicKey::MscapiRsaPublicKey(Scoped<crypt::Key> key, CK_BBOOL token) :
	value(key)
{
	this->propToken = token;
	*this->propLabel = "RSA public key";
}

MscapiRsaPublicKey::~MscapiRsaPublicKey()
{
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetID)
{
	try {
		return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)this->id.c_str(), this->id.length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetStartDate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetEndDate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetDerive)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetLocal)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetKeyGenMechanism)
{
	try {
		return this->GetNumber(pValue, pulValueLen, CKM_RSA_PKCS);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetAllowedMechanisms)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetSubject)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetEncrypt)
{
	try {
		return this->GetBool(pValue, pulValueLen, this->value->GetProvider()->GetKeySpec() & AT_KEYEXCHANGE == AT_KEYEXCHANGE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetVerify)
{
	try {
		return this->GetBool(pValue, pulValueLen, this->value->GetProvider()->GetKeySpec() & AT_SIGNATURE == AT_SIGNATURE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetVerifyRecover)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetWrap)
{
	try {
		return this->GetBool(pValue, pulValueLen, this->value->GetProvider()->GetKeySpec() & AT_KEYEXCHANGE == AT_KEYEXCHANGE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetTrusted)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetWrapTemplate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetModulus)
{
	try {
		DWORD dwPublicKeyLen = 0;
		BYTE* pbPublicKey = NULL;

		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
			THROW_MSCAPI_ERROR();
		}
		pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
			THROW_MSCAPI_ERROR();
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
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetModulusBits)
{
	try {
		DWORD dwPublicKeyLen = 0;
		BYTE* pbPublicKey = NULL;

		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
			THROW_MSCAPI_ERROR();
		}
		pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
			free(pbPublicKey);
			THROW_MSCAPI_ERROR();
		}

		PUBLICKEYSTRUC* header = (PUBLICKEYSTRUC*)pbPublicKey;
		RSAPUBKEY* info = (RSAPUBKEY*)(pbPublicKey + sizeof(PUBLICKEYSTRUC));

		CK_RV rv = this->GetNumber(pValue, pulValueLen, info->bitlen);

		free(pbPublicKey);

		return rv;
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPublicKey::GetPublicExponent)
{
	try {
		DWORD dwPublicKeyLen = 0;
		BYTE* pbPublicKey = NULL;

		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, NULL, &dwPublicKeyLen)) {
			THROW_MSCAPI_ERROR();
		}
		pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
		if (!CryptExportKey(this->value->Get(), NULL, PUBLICKEYBLOB, 0, pbPublicKey, &dwPublicKeyLen)) {
			free(pbPublicKey);
			THROW_MSCAPI_ERROR();
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
	CATCH_EXCEPTION;
}
