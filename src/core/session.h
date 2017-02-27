#pragma once
#include "../pkcs11.h"
#include "object.h";

struct OBJECT_FIND
{
	bool active;
	CK_ATTRIBUTE_PTR pTemplate;
	CK_ULONG ulTemplateSize;
	CK_ULONG index;
};

class Session
{
public:
	CK_SLOT_ID SlotID;

	CK_SESSION_HANDLE     Handle;
	bool                  ReadOnly;
	CK_VOID_PTR           Application;
	CK_NOTIFY             Notify;

	// Info
	CK_STATE              State;
	CK_FLAGS              Flags;          /* see below */
	CK_ULONG              DeviceError;  /* device-dependent error code */

	// find
	OBJECT_FIND           find;

	bool digestInitialized;
	
	Session();
	~Session();

	CK_RV InitPIN
	(
		CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
		CK_ULONG          ulPinLen   /* length in bytes of the PIN */
	);

	virtual CK_RV OpenSession
	(
		CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		CK_VOID_PTR           pApplication,  /* passed to callback */
		CK_NOTIFY             Notify,        /* callback function */
		CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
	);

	virtual CK_RV CloseSession();

	CK_RV GetSessionInfo
	(
		CK_SESSION_INFO_PTR pInfo      /* receives session info */
	);

	CK_RV C_Login
	(
		CK_USER_TYPE      userType,  /* the user type */
		CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
		CK_ULONG          ulPinLen   /* the length of the PIN */
	);

	/* Object management */

	virtual CK_RV GetAttributeValue
	(
		CK_OBJECT_HANDLE  hObject,    /* the object's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	virtual CK_RV SetAttributeValue
	(
		CK_OBJECT_HANDLE  hObject,    /* the object's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	virtual CK_RV FindObjectsInit
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
		CK_ULONG          ulCount     /* attributes in search template */
	);

	virtual CK_RV FindObjects
	(
		CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
		CK_ULONG             ulMaxObjectCount,  /* max handles to get */
		CK_ULONG_PTR         pulObjectCount     /* actual # returned */
	);

	virtual CK_RV FindObjectsFinal();

	/* Message digesting */

	virtual CK_RV DigestInit
	(
		CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
	);

	virtual CK_RV Digest
	(
		CK_BYTE_PTR       pData,        /* data to be digested */
		CK_ULONG          ulDataLen,    /* bytes of data to digest */
		CK_BYTE_PTR       pDigest,      /* gets the message digest */
		CK_ULONG_PTR      pulDigestLen  /* gets digest length */
	);

	virtual CK_RV DigestUpdate
	(
		CK_BYTE_PTR       pPart,     /* data to be digested */
		CK_ULONG          ulPartLen  /* bytes of data to be digested */
	);

	virtual CK_RV DigestKey
	(
		CK_OBJECT_HANDLE  hKey       /* secret key to digest */
	);

	virtual CK_RV DigestFinal
	(
		CK_BYTE_PTR       pDigest,      /* gets the message digest */
		CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
	);

protected:
	CK_RV CheckMechanismType(CK_MECHANISM_TYPE mechanism);
	virtual Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject) = 0;

};
