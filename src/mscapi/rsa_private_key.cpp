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
