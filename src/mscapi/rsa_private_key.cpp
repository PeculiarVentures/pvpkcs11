#include "rsa_private_key.h"
#include "helper.h"

MscapiRsaPrivateKey::MscapiRsaPrivateKey(Scoped<crypt::Key> key, CK_BBOOL token) :
	value(key)
{
	this->propToken = token;
	*this->propLabel = "RSA private key";
}

MscapiRsaPrivateKey::~MscapiRsaPrivateKey()
{
}

CK_RV MscapiRsaPrivateKey::GetKeyStruct(RsaPrivateKeyStruct* rsaKey)
{
	try {
		if (rsaKey == NULL) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "Parameter rsaKey is NULL");
		}

		THROW_PKCS11_EXCEPTION(CKR_FUNCTION_NOT_SUPPORTED, "Function is not implemented");
	}
	CATCH_EXCEPTION;
}

// Storage
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetToken)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetPrivate)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetModifiable)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetLabel)
{
	try {
		std::string label("RSA Private key");
		return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)label.c_str(), label.length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetCopyable)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

// Key
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetID)
{
	try {
		return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)id.c_str(), id.length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetStartDate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetEndDate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetDerive)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetLocal)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetKeyGenMechanism)
{
	try {
		return this->GetNumber(pValue, pulValueLen, CKK_RSA);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAllowedMechanisms)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

// Private
DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSubject)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSensitive)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetDecrypt)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSign)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetSignRecover)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetUnwrap)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetExtractable)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAlwaysSensitive)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetNeverExtractable)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_TRUE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetWrapWithTrusted)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetUnwrapTemplate)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiRsaPrivateKey::GetAlwaysAuthenticate)
{
	try {
		return this->GetBool(pValue, pulValueLen, CK_FALSE);
	}
	CATCH_EXCEPTION;
}
