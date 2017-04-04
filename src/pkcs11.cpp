#include "stdafx.h"
#include "core/module.h"
#include "mscapi/slot.h"

static CK_FUNCTION_LIST functionList =
{
	// Version information
	{ CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR },
	// Function pointers
	C_Initialize,
	C_Finalize,
	C_GetInfo,
	C_GetFunctionList,
	C_GetSlotList,
	C_GetSlotInfo,
	C_GetTokenInfo,
	C_GetMechanismList,
	C_GetMechanismInfo,
	C_InitToken,
	C_InitPIN,
	C_SetPIN,
	C_OpenSession,
	C_CloseSession,
	C_CloseAllSessions,
	C_GetSessionInfo,
	C_GetOperationState,
	C_SetOperationState,
	C_Login,
	C_Logout,
	C_CreateObject,
	C_CopyObject,
	C_DestroyObject,
	C_GetObjectSize,
	C_GetAttributeValue,
	C_SetAttributeValue,
	C_FindObjectsInit,
	C_FindObjects,
	C_FindObjectsFinal,
	C_EncryptInit,
	C_Encrypt,
	C_EncryptUpdate,
	C_EncryptFinal,
	C_DecryptInit,
	C_Decrypt,
	C_DecryptUpdate,
	C_DecryptFinal,
	C_DigestInit,
	C_Digest,
	C_DigestUpdate,
	C_DigestKey,
	C_DigestFinal,
	C_SignInit,
	C_Sign,
	C_SignUpdate,
	C_SignFinal,
	C_SignRecoverInit,
	C_SignRecover,
	C_VerifyInit,
	C_Verify,
	C_VerifyUpdate,
	C_VerifyFinal,
	C_VerifyRecoverInit,
	C_VerifyRecover,
	C_DigestEncryptUpdate,
	C_DecryptDigestUpdate,
	C_SignEncryptUpdate,
	C_DecryptVerifyUpdate,
	C_GenerateKey,
	C_GenerateKeyPair,
	C_WrapKey,
	C_UnwrapKey,
	C_DeriveKey,
	C_SeedRandom,
	C_GenerateRandom,
	C_GetFunctionStatus,
	C_CancelFunction,
	C_WaitForSlotEvent
};

Module pkcs11 = Module();

class App {
public:
	App() {
		Scoped<Slot> mscapiSlot(new MscapiSlot());
		pkcs11.slots.add(mscapiSlot);
		mscapiSlot->slotID = pkcs11.slots.count() - 1;
	}
};

App app = App();


CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionList)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{
	try {
		CHECK_ARGUMENT_NULL(ppFunctionList);

		*ppFunctionList = &functionList;

		return CKR_OK;
	}
	catch (...)
	{

	}

	return CKR_FUNCTION_FAILED;
}

// PKCS #11 initialization function
CK_DEFINE_FUNCTION(CK_RV, C_Initialize)(CK_VOID_PTR pInitArgs)
{
	try {
		return pkcs11.Initialize(pInitArgs);
	}
	catch (...) {

	}

	return CKR_FUNCTION_FAILED;
}

// PKCS #11 finalization function
CK_DEFINE_FUNCTION(CK_RV, C_Finalize)(CK_VOID_PTR pReserved)
{
	try {
		return pkcs11.Finalize(pReserved);
	}
	catch (...)
	{

	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetInfo)(CK_INFO_PTR pInfo)
{
	try
	{
		return pkcs11.GetInfo(pInfo);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotList)(
	CK_BBOOL       tokenPresent,  /* only slots with tokens? */
	CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
	CK_ULONG_PTR   pulCount       /* receives number of slots */
	)
{
	try
	{
		return pkcs11.GetSlotList(tokenPresent, pSlotList, pulCount);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSlotInfo)(
	CK_SLOT_ID       slotID,  /* the ID of the slot */
	CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
	)
{
	try
	{
		return pkcs11.GetSlotInfo(slotID, pInfo);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetTokenInfo)
(
	CK_SLOT_ID        slotID,  /* ID of the token's slot */
	CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
	)
{
	try
	{
		return pkcs11.GetTokenInfo(slotID, pInfo);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismList)
(
	CK_SLOT_ID            slotID,          /* ID of token's slot */
	CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mechanism array */
	CK_ULONG_PTR          pulCount         /* gets # of mechanisms */
	)
{
	try
	{
		return pkcs11.GetMechanismList(slotID, pMechanismList, pulCount);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetMechanismInfo)
(
	CK_SLOT_ID            slotID,  /* ID of the token's slot */
	CK_MECHANISM_TYPE     type,    /* type of mechanism */
	CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
	)
{
	try
	{
		return pkcs11.GetMechanismInfo(slotID, type, pInfo);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitToken)
(
	CK_SLOT_ID      slotID,    /* ID of the token's slot */
	CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
	CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
	CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
	)
{
	try
	{
		return pkcs11.InitToken(slotID, pPin, ulPinLen, pLabel);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_InitPIN)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	CK_ULONG          ulPinLen   /* length in bytes of the PIN */
	)
{
	try
	{
		return pkcs11.InitPIN(hSession, pPin, ulPinLen);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetPIN)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_UTF8CHAR_PTR   pOldPin,   /* the old PIN */
	CK_ULONG          ulOldLen,  /* length of the old PIN */
	CK_UTF8CHAR_PTR   pNewPin,   /* the new PIN */
	CK_ULONG          ulNewLen   /* length of the new PIN */
	)
{
	try
	{
		// return pkcs11.SetPIN(hSession, pOldPin, ulOldLen, pNewPin, ulNewLen);
	}
	catch (...)
	{
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_OpenSession)
(
	CK_SLOT_ID            slotID,        /* the slot's ID */
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
	)
{
	try
	{
		return pkcs11.OpenSession(slotID, flags, pApplication, Notify, phSession);
	}
	catch (...)
	{
		puts("Error: C_OpenSession");
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseSession)
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
	)
{
	try
	{
		return pkcs11.CloseSession(hSession);
	}
	catch (...)
	{
		puts("Error: C_CloseSession");
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_CloseAllSessions)
(
	CK_SLOT_ID     slotID  /* the token's slot */
	)
{
	try
	{
		return pkcs11.CloseAllSessions(slotID);
	}
	catch (...)
	{
		puts("Error: C_CloseAllSessions");
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetSessionInfo)
(
	CK_SESSION_HANDLE   hSession,  /* the session's handle */
	CK_SESSION_INFO_PTR pInfo      /* receives session info */
	)
{
	try
	{
		return pkcs11.GetSessionInfo(hSession, pInfo);
	}
	catch (...)
	{
		puts("Error: C_CloseAllSessions");
	}

	return CKR_FUNCTION_FAILED;
}

CK_DEFINE_FUNCTION(CK_RV, C_GetOperationState)
(
	CK_SESSION_HANDLE hSession,             /* session's handle */
	CK_BYTE_PTR       pOperationState,      /* gets state */
	CK_ULONG_PTR      pulOperationStateLen  /* gets state length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_SetOperationState)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR      pOperationState,      /* holds state */
	CK_ULONG         ulOperationStateLen,  /* holds state length */
	CK_OBJECT_HANDLE hEncryptionKey,       /* en/decryption key */
	CK_OBJECT_HANDLE hAuthenticationKey    /* sign/verify key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_DEFINE_FUNCTION(CK_RV, C_Login)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_USER_TYPE      userType,  /* the user type */
	CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
	CK_ULONG          ulPinLen   /* the length of the PIN */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_DEFINE_FUNCTION(CK_RV, C_Logout)
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/* Object management */

/* C_CreateObject creates a new object. */
CK_DEFINE_FUNCTION(CK_RV, C_CreateObject)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_ATTRIBUTE_PTR  pTemplate,   /* the object's template */
	CK_ULONG          ulCount,     /* attributes in template */
	CK_OBJECT_HANDLE_PTR phObject  /* gets new object's handle. */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_CopyObject copies an object, creating a new object for the
* copy. */
CK_DEFINE_FUNCTION(CK_RV, C_CopyObject)
(
	CK_SESSION_HANDLE    hSession,    /* the session's handle */
	CK_OBJECT_HANDLE     hObject,     /* the object's handle */
	CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
	CK_ULONG             ulCount,     /* attributes in template */
	CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DestroyObject destroys an object. */
CK_DEFINE_FUNCTION(CK_RV, C_DestroyObject)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_OBJECT_HANDLE  hObject    /* the object's handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GetObjectSize gets the size of an object in bytes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetObjectSize)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_OBJECT_HANDLE  hObject,   /* the object's handle */
	CK_ULONG_PTR      pulSize    /* receives size of object */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GetAttributeValue obtains the value of one or more object
* attributes. */
CK_DEFINE_FUNCTION(CK_RV, C_GetAttributeValue)
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
	CK_ULONG          ulCount     /* attributes in template */
	)
{
	try {
		return pkcs11.GetAttributeValue(hSession, hObject, pTemplate, ulCount);
	}
	catch (...) {
		puts("Error: C_GetAttributeValue");
	}

	return CKR_FUNCTION_FAILED;
}


/* C_SetAttributeValue modifies the value of one or more object
* attributes */
CK_DEFINE_FUNCTION(CK_RV, C_SetAttributeValue)
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_FindObjectsInit initializes a search for token and session
* objects that match a template. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsInit)
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
	CK_ULONG          ulCount     /* attributes in search template */
	)
{
	try {
		return pkcs11.FindObjectsInit(hSession, pTemplate, ulCount);
	}
	catch (...) {
		puts("Error: C_FindObjectsInit");
	}

	return CKR_FUNCTION_FAILED;
}


/* C_FindObjects continues a search for token and session
* objects that match a template, obtaining additional object
* handles. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjects)
(
	CK_SESSION_HANDLE    hSession,          /* session's handle */
	CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
	CK_ULONG             ulMaxObjectCount,  /* max handles to get */
	CK_ULONG_PTR         pulObjectCount     /* actual # returned */
	)
{
	try {
		return pkcs11.FindObjects(hSession, phObject, ulMaxObjectCount, pulObjectCount);
	}
	catch (...) {
		puts("Error: C_FindObjects");
	}

	return CKR_FUNCTION_FAILED;
}


/* C_FindObjectsFinal finishes a search for token and session
* objects. */
CK_DEFINE_FUNCTION(CK_RV, C_FindObjectsFinal)
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
	)
{
	try {
		return pkcs11.FindObjectsFinal(hSession);
	}
	catch (...) {
		puts("Error: C_FindObjectsFinal");
	}

	return CKR_FUNCTION_FAILED;
}



/* Encryption and decryption */

/* C_EncryptInit initializes an encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptInit)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Encrypt encrypts single-part data. */
CK_DEFINE_FUNCTION(CK_RV, C_Encrypt)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pData,               /* the plaintext data */
	CK_ULONG          ulDataLen,           /* bytes of plaintext */
	CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_EncryptUpdate continues a multiple-part encryption
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptUpdate)
(
	CK_SESSION_HANDLE hSession,           /* session's handle */
	CK_BYTE_PTR       pPart,              /* the plaintext data */
	CK_ULONG          ulPartLen,          /* plaintext data length */
	CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_EncryptFinal finishes a multiple-part encryption
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_EncryptFinal)
(
	CK_SESSION_HANDLE hSession,                /* session handle */
	CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
	CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptInit initializes a decryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptInit)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Decrypt decrypts encrypted data in a single part. */
CK_DEFINE_FUNCTION(CK_RV, C_Decrypt)
(
	CK_SESSION_HANDLE hSession,           /* session's handle */
	CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
	CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
	CK_BYTE_PTR       pData,              /* gets plaintext */
	CK_ULONG_PTR      pulDataLen          /* gets p-text size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptUpdate continues a multiple-part decryption
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptUpdate)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
	CK_ULONG          ulEncryptedPartLen,  /* input length */
	CK_BYTE_PTR       pPart,               /* gets plaintext */
	CK_ULONG_PTR      pulPartLen           /* p-text size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptFinal finishes a multiple-part decryption
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptFinal)
(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pLastPart,      /* gets plaintext */
	CK_ULONG_PTR      pulLastPartLen  /* p-text size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Message digesting */

/* C_DigestInit initializes a message-digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestInit)
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
	)
{
	try {
		return pkcs11.DigestInit(hSession, pMechanism);
	}
	catch (...) {
	}

	return CKR_FUNCTION_FAILED;
}


/* C_Digest digests data in a single part. */
CK_DEFINE_FUNCTION(CK_RV, C_Digest)
(
	CK_SESSION_HANDLE hSession,     /* the session's handle */
	CK_BYTE_PTR       pData,        /* data to be digested */
	CK_ULONG          ulDataLen,    /* bytes of data to digest */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets digest length */
	)
{
	try {
		return pkcs11.Digest(hSession, pData, ulDataLen, pDigest, pulDigestLen);
	}
	catch (...) {
	}

	return CKR_FUNCTION_FAILED;
}


/* C_DigestUpdate continues a multiple-part message-digesting
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestUpdate)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* data to be digested */
	CK_ULONG          ulPartLen  /* bytes of data to be digested */
	)
{
	try {
		return pkcs11.DigestUpdate(hSession, pPart, ulPartLen);
	}
	catch (...) {
	}

	return CKR_FUNCTION_FAILED;
}


/* C_DigestKey continues a multi-part message-digesting
* operation, by digesting the value of a secret key as part of
* the data already digested. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestKey)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_OBJECT_HANDLE  hKey       /* secret key to digest */
	)
{
	try {
		return pkcs11.DigestKey(hSession, hKey);
	}
	catch (...) {
	}

	return CKR_FUNCTION_FAILED;
}


/* C_DigestFinal finishes a multiple-part message-digesting
* operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestFinal)
(
	CK_SESSION_HANDLE hSession,     /* the session's handle */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
	)
{
	try {
		return pkcs11.DigestFinal(hSession, pDigest, pulDigestLen);
	}
	catch (...) {
	}

	return CKR_FUNCTION_FAILED;
}



/* Signing and MACing */

/* C_SignInit initializes a signature (private key encryption)
* operation, where the signature is (will be) an appendix to
* the data, and plaintext cannot be recovered from the
*signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignInit)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of signature key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Sign signs (encrypts with private key) data in a single
* part, where the signature is (will be) an appendix to the
* data, and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Sign)
(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignUpdate continues a multiple-part signature operation,
* where the signature is (will be) an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignUpdate)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* the data to sign */
	CK_ULONG          ulPartLen  /* count of bytes to sign */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignFinal finishes a multiple-part signature operation,
* returning the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignFinal)
(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecoverInit initializes a signature operation, where
* the data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecoverInit)
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_MECHANISM_PTR  pMechanism, /* the signature mechanism */
	CK_OBJECT_HANDLE  hKey        /* handle of the signature key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignRecover signs data in a single operation, where the
* data can be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_SignRecover)
(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Verifying signatures and MACs */

/* C_VerifyInit initializes a verification operation, where the
* signature is an appendix to the data, and plaintext cannot
*  cannot be recovered from the signature (e.g. DSA). */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyInit)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_Verify verifies a signature in a single-part operation,
* where the signature is an appendix to the data, and plaintext
* cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_Verify)
(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pData,          /* signed data */
	CK_ULONG          ulDataLen,      /* length of signed data */
	CK_BYTE_PTR       pSignature,     /* signature */
	CK_ULONG          ulSignatureLen  /* signature length*/
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyUpdate continues a multiple-part verification
* operation, where the signature is an appendix to the data,
* and plaintext cannot be recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyUpdate)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyFinal finishes a multiple-part verification
* operation, checking the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyFinal)
(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pSignature,     /* signature to verify */
	CK_ULONG          ulSignatureLen  /* signature length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecoverInit initializes a signature verification
* operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecoverInit)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_VerifyRecover verifies a signature in a single-part
* operation, where the data is recovered from the signature. */
CK_DEFINE_FUNCTION(CK_RV, C_VerifyRecover)
(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pSignature,      /* signature to verify */
	CK_ULONG          ulSignatureLen,  /* signature length */
	CK_BYTE_PTR       pData,           /* gets signed data */
	CK_ULONG_PTR      pulDataLen       /* gets signed data length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Dual-function cryptographic operations */

/* C_DigestEncryptUpdate continues a multiple-part digesting
* and encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DigestEncryptUpdate)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pPart,               /* the plaintext data */
	CK_ULONG          ulPartLen,           /* plaintext length */
	CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptDigestUpdate continues a multiple-part decryption and
* digesting operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptDigestUpdate)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
	CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
	CK_BYTE_PTR       pPart,               /* gets plaintext */
	CK_ULONG_PTR      pulPartLen           /* gets plaintext length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_SignEncryptUpdate continues a multiple-part signing and
* encryption operation. */
CK_DEFINE_FUNCTION(CK_RV, C_SignEncryptUpdate)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pPart,               /* the plaintext data */
	CK_ULONG          ulPartLen,           /* plaintext length */
	CK_BYTE_PTR       pEncryptedPart,      /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedPartLen  /* gets c-text length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DecryptVerifyUpdate continues a multiple-part decryption and
* verify operation. */
CK_DEFINE_FUNCTION(CK_RV, C_DecryptVerifyUpdate)
(
	CK_SESSION_HANDLE hSession,            /* session's handle */
	CK_BYTE_PTR       pEncryptedPart,      /* ciphertext */
	CK_ULONG          ulEncryptedPartLen,  /* ciphertext length */
	CK_BYTE_PTR       pPart,               /* gets plaintext */
	CK_ULONG_PTR      pulPartLen           /* gets p-text length */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Key management */

/* C_GenerateKey generates a secret key, creating a new key
* object. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKey)
(
	CK_SESSION_HANDLE    hSession,    /* the session's handle */
	CK_MECHANISM_PTR     pMechanism,  /* key generation mechanism */
	CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
	CK_ULONG             ulCount,     /* # of attributes in template */
	CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GenerateKeyPair generates a public-key/private-key pair,
* creating new key objects. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateKeyPair)
(
	CK_SESSION_HANDLE    hSession,                    /* session
													  * handle */
	CK_MECHANISM_PTR     pMechanism,                  /* key-gen
													  * mechanism */
	CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template
													  * for pub.
													  * key */
	CK_ULONG             ulPublicKeyAttributeCount,   /* # pub.
													  * attributes */
	CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template
													  * for private
													  * key */
	CK_ULONG             ulPrivateKeyAttributeCount,  /* # private
													  * attributes */
	CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub.
													  * key
													  * handle */
	CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets
													  * private key
													  * handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_WrapKey wraps (i.e., encrypts) a key. */
CK_DEFINE_FUNCTION(CK_RV, C_WrapKey)
(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,      /* the wrapping mechanism */
	CK_OBJECT_HANDLE  hWrappingKey,    /* wrapping key */
	CK_OBJECT_HANDLE  hKey,            /* key to be wrapped */
	CK_BYTE_PTR       pWrappedKey,     /* gets wrapped key */
	CK_ULONG_PTR      pulWrappedKeyLen /* gets wrapped key size */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_UnwrapKey unwraps (decrypts) a wrapped key, creating a new
* key object. */
CK_DEFINE_FUNCTION(CK_RV, C_UnwrapKey)
(
	CK_SESSION_HANDLE    hSession,          /* session's handle */
	CK_MECHANISM_PTR     pMechanism,        /* unwrapping mechanism */
	CK_OBJECT_HANDLE     hUnwrappingKey,    /* unwrapping key */
	CK_BYTE_PTR          pWrappedKey,       /* the wrapped key */
	CK_ULONG             ulWrappedKeyLen,   /* wrapped key length */
	CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
	CK_ULONG             ulAttributeCount,  /* template length */
	CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_DeriveKey derives a key from a base key, creating a new key
* object. */
CK_DEFINE_FUNCTION(CK_RV, C_DeriveKey)
(
	CK_SESSION_HANDLE    hSession,          /* session's handle */
	CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
	CK_OBJECT_HANDLE     hBaseKey,          /* base key */
	CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
	CK_ULONG             ulAttributeCount,  /* template length */
	CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Random number generation */

/* C_SeedRandom mixes additional seed material into the token's
* random number generator. */
CK_DEFINE_FUNCTION(CK_RV, C_SeedRandom)
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pSeed,     /* the seed material */
	CK_ULONG          ulSeedLen  /* length of seed material */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_GenerateRandom generates random data. */
CK_DEFINE_FUNCTION(CK_RV, C_GenerateRandom)
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       RandomData,  /* receives the random data */
	CK_ULONG          ulRandomLen  /* # of bytes to generate */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Parallel function management */

/* C_GetFunctionStatus is a legacy function; it obtains an
* updated status of a function running in parallel with an
* application. */
CK_DEFINE_FUNCTION(CK_RV, C_GetFunctionStatus)
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}


/* C_CancelFunction is a legacy function; it cancels a function
* running in parallel. */
CK_DEFINE_FUNCTION(CK_RV, C_CancelFunction)
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}



/* Functions added in for Cryptoki Version 2.01 or later */

/* C_WaitForSlotEvent waits for a slot event (token insertion,
* removal, etc.) to occur. */
CK_DEFINE_FUNCTION(CK_RV, C_WaitForSlotEvent)
(
	CK_FLAGS flags,        /* blocking/nonblocking flag */
	CK_SLOT_ID_PTR pSlot,  /* location that receives the slot ID */
	CK_VOID_PTR pRserved   /* reserved.  Should be NULL_PTR */
	)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}
