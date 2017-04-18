#include "rsa_private_key.h"
#include "helper.h"

MscapiRsaPrivateKey::MscapiRsaPrivateKey(HCRYPTPROV hProv, HCRYPTKEY hKey)
{
	this->hProv = hProv;
	this->hKey = hKey;
}

MscapiRsaPrivateKey::~MscapiRsaPrivateKey()
{
	if (hProv) {
		CryptReleaseContext(hProv, 0);
		hProv = NULL;
	}
	if (hKey) {
		CryptDestroyKey(hKey);
		hKey = NULL;
	}
}

CK_RV MscapiRsaPrivateKey::GetKeyStruct(RsaPrivateKeyStruct* rsaKey)
{
	if (rsaKey == NULL) {
		puts("MscapiRsaPrivateKey::GetKeyStruct: Parameter rsaKey is NULL");
		return ERROR_BAD_ARGUMENTS;
	}

	puts("MscapiRsaPrivateKey::GetKeyStruct: Function is not implemented");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

// Storage
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetToken)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetPrivate)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetModifiable)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetLabel)
{
	std::string label("RSA Private key");
	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)label.c_str(), label.length());
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetCopyable)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

// Key
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetID)
{
	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)id.c_str(), id.length());
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetStartDate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetEndDate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetDerive)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetLocal)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetKeyGenMechanism)
{
	return this->GetNumber(pValue, pulValueLen, CKK_RSA);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAllowedMechanisms)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

// Private
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSubject)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSensitive)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetDecrypt)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSign)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSignRecover)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetUnwrap)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetExtractable)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAlwaysSensitive)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetNeverExtractable)
{
	return this->GetBool(pValue, pulValueLen, CK_TRUE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetWrapWithTrusted)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetUnwrapTemplate)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAlwaysAuthenticate) 
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}
