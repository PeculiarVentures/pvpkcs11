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
