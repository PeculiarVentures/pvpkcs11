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

protected:
	HCRYPTPROV hRsaAesProv;
	Scoped<crypt::Hash> hash;
	Scoped<crypt::Verify> verify;
	Scoped<crypt::Sign> sign;
	Collection<Scoped<crypt::CertStore>> certStores;
	Collection<Scoped<Object>> objects;
	virtual Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject);
	void LoadMyStore();

	CK_BBOOL TEMPLATES_EQUALS(CK_ATTRIBUTE_PTR pTemplate1, CK_ULONG ulTemplate1Size, CK_ATTRIBUTE_PTR pTemplate2, CK_ULONG ulTemplate2Size);
};
