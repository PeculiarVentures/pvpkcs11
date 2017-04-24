#include "../stdafx.h"
#include "module.h"

#define CHECK_INITIALIZED()						\
	if (!this->initialized) {					\
		return CKR_CRYPTOKI_NOT_INITIALIZED;	\
	}

#define CHECK_SLOD_ID(slotID)									\
	if (!(slotID >= 0 && slotID < this->slots.count())) {		\
		return CKR_SLOT_ID_INVALID;								\
	}

#define GET_SESSION(hSession)                                           \
	Scoped<Session> session = this->getSession(hSession);               \
	if (!session) {                                                     \
		return CKR_SESSION_HANDLE_INVALID;                              \
	}

Module::Module() {
	this->initialized = false;
}

CK_RV Module::Initialize(CK_VOID_PTR   pInitArgs) {
	if (this->initialized) {
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}
	this->initialized = true;
	return CKR_OK;
}

CK_RV Module::Finalize(CK_VOID_PTR pReserved) {
	CHECK_INITIALIZED();
	return CKR_OK;
}

CK_RV Module::GetInfo(CK_INFO_PTR pInfo) {
	CHECK_INITIALIZED();
	CHECK_ARGUMENT_NULL(pInfo);

	pInfo->cryptokiVersion = { CRYPTOKI_VERSION_MAJOR, CRYPTOKI_VERSION_MINOR };
	pInfo->flags = 0;
	SET_STRING(pInfo->manufacturerID, "Module", 32);
	SET_STRING(pInfo->libraryDescription, "Windows CryptoAPI", 32);
	pInfo->libraryVersion = { 0, 1 };

	return CKR_OK;
}

CK_RV Module::GetSlotList(
	CK_BBOOL       tokenPresent,  /* only slots with tokens? */
	CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
	CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
	CHECK_INITIALIZED();
	if (pSlotList == NULL_PTR) {
		*pulCount = this->slots.count();
	}
	else {
		if (*pulCount < this->slots.count()) {
			return CKR_BUFFER_TOO_SMALL;
		}
		for (size_t i = 0; i < this->slots.count(); i++) {
			pSlotList[i] = i;
		}
	}
	return CKR_OK;
}

CK_RV Module::GetSlotInfo(
	CK_SLOT_ID       slotID,  /* the ID of the slot */
	CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);
	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->GetSlotInfo(pInfo);
}

CK_RV Module::GetTokenInfo
(
	CK_SLOT_ID        slotID,  /* ID of the token's slot */
	CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);
	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->GetTokenInfo(pInfo);
}

CK_RV Module::GetMechanismList
(
	CK_SLOT_ID            slotID,          /* ID of token's slot */
	CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
	CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);
	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->GetMechanismList(pMechanismList, pulCount);
}

CK_RV Module::GetMechanismInfo
(
	CK_SLOT_ID            slotID,  /* ID of the token's slot */
	CK_MECHANISM_TYPE     type,    /* type of mechanism */
	CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);
	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->GetMechanismInfo(type, pInfo);
}

CK_RV Module::InitToken
(
	CK_SLOT_ID      slotID,    /* ID of the token's slot */
	CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
	CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
	CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);

	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->InitToken(pPin, ulPinLen, pLabel);
}

CK_RV Module::InitPIN
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	CHECK_INITIALIZED();
}

CK_RV Module::OpenSession
(
	CK_SLOT_ID            slotID,        /* the slot's ID */
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);

	Scoped<Slot> slot = this->slots.items(slotID);
	return slot->OpenSession(flags, pApplication, Notify, phSession);
}

CK_RV Module::CloseSession
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CHECK_INITIALIZED();
	Scoped<Slot> slot = this->getSlotBySession(hSession);

	if (slot == NULL_PTR) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	return slot->CloseSession(hSession);
}

Scoped<Slot> Module::getSlotBySession(CK_SESSION_HANDLE hSession)
{
	for (size_t i = 0; i < this->slots.count(); i++) {
		Scoped<Slot> slot = this->slots.items(i);
		if (slot->hasSession(hSession)) {
			return slot;
		}
	}
	return NULL_PTR;
}

Scoped<Session> Module::getSession(CK_SESSION_HANDLE hSession)
{
	Scoped<Slot> slot = this->getSlotBySession(hSession);
	if (slot) {
		Scoped<Session> session = slot->getSession(hSession);
		return session;
	}

	return NULL_PTR;
}

CK_RV Module::CloseAllSessions
(
	CK_SLOT_ID     slotID  /* the token's slot */
)
{
	CHECK_INITIALIZED();
	CHECK_SLOD_ID(slotID);
	Scoped<Slot> slot = this->slots.items(slotID);

	return slot->CloseAllSessions();
}

CK_RV Module::GetSessionInfo
(
	CK_SESSION_HANDLE   hSession,  /* the session's handle */
	CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->GetSessionInfo(pInfo);
}

CK_RV Module::Login
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_USER_TYPE      userType,  /* the user type */
	CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
	CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Login(userType, pPin, ulPinLen);
}

CK_RV Module::GetAttributeValue
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->GetAttributeValue(hObject, pTemplate, ulCount);
}

CK_RV Module::SetAttributeValue
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->SetAttributeValue(hObject, pTemplate, ulCount);
}

CK_RV Module::FindObjectsInit
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
	CK_ULONG          ulCount     /* attributes in search template */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->FindObjectsInit(pTemplate, ulCount);
}

CK_RV Module::FindObjects
(
	CK_SESSION_HANDLE    hSession,          /* session's handle */
	CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
	CK_ULONG             ulMaxObjectCount,  /* max handles to get */
	CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->FindObjects(phObject, ulMaxObjectCount, pulObjectCount);
}

CK_RV Module::FindObjectsFinal
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->FindObjectsFinal();
}

CK_RV Module::DigestInit
(
	CK_SESSION_HANDLE hSession,   /* the session's handle */
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DigestInit(pMechanism);
}

CK_RV Module::Digest
(
	CK_SESSION_HANDLE hSession,     /* the session's handle */
	CK_BYTE_PTR       pData,        /* data to be digested */
	CK_ULONG          ulDataLen,    /* bytes of data to digest */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Digest(pData, ulDataLen, pDigest, pulDigestLen);
}

CK_RV Module::DigestUpdate
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* data to be digested */
	CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DigestUpdate(pPart, ulPartLen);
}

CK_RV Module::DigestKey
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);
}

CK_RV Module::DigestFinal
(
	CK_SESSION_HANDLE hSession,     /* the session's handle */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DigestFinal(pDigest, pulDigestLen);
}

/* Signing and MACing */

CK_RV Module::SignInit(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->SignInit(pMechanism, hKey);
}

CK_RV Module::Sign(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Sign(pData, ulDataLen, pSignature, pulSignatureLen);
}

CK_RV Module::SignUpdate(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* the data to sign */
	CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->SignUpdate(pPart, ulPartLen);
}

CK_RV Module::SignFinal(
	CK_SESSION_HANDLE hSession,        /* the session's handle */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->SignFinal(pSignature, pulSignatureLen);
}

CK_RV Module::VerifyInit
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->VerifyInit(pMechanism, hKey);
}

CK_RV Module::Verify
(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pData,          /* signed data */
	CK_ULONG          ulDataLen,      /* length of signed data */
	CK_BYTE_PTR       pSignature,     /* signature */
	CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Verify(pData, ulDataLen, pSignature, ulSignatureLen);
}

CK_RV Module::VerifyUpdate
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->VerifyUpdate(pPart, ulPartLen);
}

CK_RV Module::VerifyFinal
(
	CK_SESSION_HANDLE hSession,       /* the session's handle */
	CK_BYTE_PTR       pSignature,     /* signature to verify */
	CK_ULONG          ulSignatureLen  /* signature length */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->VerifyFinal(pSignature, ulSignatureLen);
}

CK_RV Module::EncryptInit
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->EncryptInit(pMechanism, hKey);
}

CK_RV Module::Encrypt
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pData,               /* the plaintext data */
	CK_ULONG          ulDataLen,           /* bytes of plaintext */
	CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Encrypt(
		pData,
		ulDataLen,
		pEncryptedData,
		pulEncryptedDataLen
	);
}

CK_RV Module::EncryptUpdate
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pPart,              /* the plaintext data */
	CK_ULONG          ulPartLen,          /* plaintext data len */
	CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->EncryptUpdate(
		pPart,
		ulPartLen,
		pEncryptedPart,
		pulEncryptedPartLen
	);
}

CK_RV Module::EncryptFinal
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
	CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->EncryptFinal(
		pLastEncryptedPart,
		pulLastEncryptedPartLen
	);
}

CK_RV Module::DecryptInit
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DecryptInit(
		pMechanism,
		hKey
	);
}

CK_RV Module::Decrypt
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
	CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
	CK_BYTE_PTR       pData,              /* gets plaintext */
	CK_ULONG_PTR      pulDataLen          /* gets p-text size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->Decrypt(
		pEncryptedData,
		ulEncryptedDataLen,
		pData,
		pulDataLen
	);
}

CK_RV Module::DecryptUpdate
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
	CK_ULONG          ulEncryptedPartLen,  /* input length */
	CK_BYTE_PTR       pPart,               /* gets plaintext */
	CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DecryptUpdate(
		pEncryptedPart,
		ulEncryptedPartLen,
		pPart,
		pulPartLen
	);
}

CK_RV Module::DecryptFinal
(
	CK_SESSION_HANDLE hSession,    /* the session's handle */
	CK_BYTE_PTR       pLastPart,      /* gets plaintext */
	CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->DecryptFinal(
		pLastPart,
		pulLastPartLen
	);
}

CK_RV Module::GenerateKey
(
	CK_SESSION_HANDLE    hSession,    /* the session's handle */
	CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
	CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
	CK_ULONG             ulCount,     /* # of attrs in template */
	CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
	CHECK_INITIALIZED();
	GET_SESSION(hSession);

	return session->GenerateKey(
		pMechanism,
		pTemplate,
		ulCount,
		phKey
	);
}