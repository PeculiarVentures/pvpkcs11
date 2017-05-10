#include "crypto.h"

#include "excep.h"

using namespace core;

CK_RV CryptoDigest::Init
(
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	try {
		if (active) {
			THROW_PKCS11_OPERATION_ACTIVE();
		}
		if (pMechanism == NULL_PTR) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
		}
	}
	CATCH_EXCEPTION;
}

CK_RV CryptoDigest::Once(
	CK_BYTE_PTR       pData,        /* data to be digested */
	CK_ULONG          ulDataLen,    /* bytes of data to digest */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	try {
		if (pDigest) {
			Update(pData, ulDataLen);
		}
		return Final(pDigest, pulDigestLen);
	}
	CATCH_EXCEPTION;
}

CK_RV CryptoDigest::Update(
	CK_BYTE_PTR       pPart,     /* data to be digested */
	CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	try {
		if (!active) {
			THROW_PKCS11_OPERATION_NOT_INITIALIZED();
		}
		if (pPart == NULL_PTR) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pPart is NULL");
		}
	}
	CATCH_EXCEPTION;
}

CK_RV CryptoDigest::Key(
	Scoped<Object>    key
)
{
	try {
		if (!active) {
			THROW_PKCS11_OPERATION_NOT_INITIALIZED();
		}
		if (!(key && key.get())) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
		}
		if (!dynamic_cast<SecretKey*>(key.get())) {
			THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not SecretKey");
		}
	}
	CATCH_EXCEPTION;
}


CK_RV CryptoDigest::Final(
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	try {
		if (!active) {
			THROW_PKCS11_OPERATION_NOT_INITIALIZED();
		}
	}
	CATCH_EXCEPTION;
}