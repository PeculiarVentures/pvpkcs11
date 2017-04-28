#pragma once

#include "../core/session.h"
#include "crypt/crypt.h"

class MscapiSession : public Session
{
public:
	MscapiSession();
	~MscapiSession();

	CK_RV OpenSession
	(
		CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		CK_VOID_PTR           pApplication,  /* passed to callback */
		CK_NOTIFY             Notify,        /* callback function */
		CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
	);

	CK_RV CloseSession();

	/* Object management */

	CK_RV FindObjectsInit
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
		CK_ULONG          ulCount     /* attributes in search template */
	);

	CK_RV FindObjects
	(
		CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
		CK_ULONG             ulMaxObjectCount,  /* max handles to get */
		CK_ULONG_PTR         pulObjectCount     /* actual # returned */
	);

	CK_RV FindObjectsFinal();

	CK_RV DigestInit
	(
		CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
	);

	CK_RV DigestUpdate
	(
		CK_BYTE_PTR       pPart,     /* data to be digested */
		CK_ULONG          ulPartLen  /* bytes of data to be digested */
	);

	CK_RV DigestKey
	(
		CK_OBJECT_HANDLE  hKey       /* secret key to digest */
	);

	CK_RV DigestFinal
	(
		CK_BYTE_PTR       pDigest,      /* gets the message digest */
		CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
	);

	// Message verification

	CK_RV VerifyInit(
		CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
		CK_OBJECT_HANDLE  hKey         /* verification key */
	);

	CK_RV VerifyUpdate(
		CK_BYTE_PTR       pPart,     /* signed data */
		CK_ULONG          ulPartLen  /* length of signed data */
	);

	CK_RV VerifyFinal(
		CK_BYTE_PTR       pSignature,     /* signature to verify */
		CK_ULONG          ulSignatureLen  /* signature length */
	);

	// Message signing

	CK_RV SignInit(
		CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of signature key */
	);

	CK_RV SignUpdate(
		CK_BYTE_PTR       pPart,     /* the data to sign */
		CK_ULONG          ulPartLen  /* count of bytes to sign */
	);

	CK_RV SignFinal(
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	);

	/* Encryption and decryption */

	CK_RV EncryptInit
	(
		CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
	);

	CK_RV EncryptUpdate
	(
		CK_BYTE_PTR       pPart,              /* the plaintext data */
		CK_ULONG          ulPartLen,          /* plaintext data len */
		CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
		CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
	);


	CK_RV EncryptFinal
	(
		CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
		CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
	);

	CK_RV DecryptInit
	(
		CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
	);

	CK_RV DecryptUpdate
	(
		CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
		CK_ULONG          ulEncryptedPartLen,  /* input length */
		CK_BYTE_PTR       pPart,               /* gets plaintext */
		CK_ULONG_PTR      pulPartLen           /* p-text size */
	);

	CK_RV DecryptFinal
	(
		CK_BYTE_PTR       pLastPart,      /* gets plaintext */
		CK_ULONG_PTR      pulLastPartLen  /* p-text size */
	);

	// Key generation

	CK_RV GenerateKey
	(
		CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
		CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
		CK_ULONG             ulCount,     /* # of attrs in template */
		CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
	);

	CK_RV GenerateKeyPair
	(
		CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
		CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
		CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
		CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
		CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
		CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
		CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
	);

protected:
	HCRYPTPROV hRsaAesProv;
	Scoped<crypt::Hash> hash;
	Scoped<crypt::Verify> verify;
	Scoped<crypt::Sign> sign;
	Scoped<crypt::Cipher> encrypt;
	Scoped<crypt::Cipher> decrypt;
	Collection<Scoped<crypt::CertStore>> certStores;
	Collection<Scoped<Object>> objects;
	virtual Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject);
	void LoadMyStore();

	CK_BBOOL TEMPLATES_EQUALS(CK_ATTRIBUTE_PTR pTemplate1, CK_ULONG ulTemplate1Size, CK_ATTRIBUTE_PTR pTemplate2, CK_ULONG ulTemplate2Size);
};
