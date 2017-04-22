#include "collection.h"
#include "slot.h"

class Module {
public:
	bool initialized;
	Collection<Scoped<Slot>> slots;

	Module(void);

	CK_RV Initialize(CK_VOID_PTR   pInitArgs);
	CK_RV Finalize(CK_VOID_PTR pReserved);
	CK_RV GetInfo(CK_INFO_PTR pInfo);

	CK_RV GetSlotList(
		CK_BBOOL       tokenPresent,  /* only slots with tokens? */
		CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
		CK_ULONG_PTR   pulCount       /* receives number of slots */
	);

	CK_RV GetSlotInfo(
		CK_SLOT_ID       slotID,  /* the ID of the slot */
		CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
	);

	CK_RV GetTokenInfo
	(
		CK_SLOT_ID        slotID,  /* ID of the token's slot */
		CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
	);

	CK_RV GetMechanismList
	(
		CK_SLOT_ID            slotID,          /* ID of token's slot */
		CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
		CK_ULONG_PTR          pulCount         /* gets # of mechs. */
	);

	CK_RV GetMechanismInfo
	(
		CK_SLOT_ID            slotID,  /* ID of the token's slot */
		CK_MECHANISM_TYPE     type,    /* type of mechanism */
		CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
	);

	CK_RV InitToken
	(
		CK_SLOT_ID      slotID,    /* ID of the token's slot */
		CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
		CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
		CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
	);

	CK_RV InitPIN
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
		CK_ULONG          ulPinLen   /* length in bytes of the PIN */
	);

	CK_RV OpenSession
	(
		CK_SLOT_ID            slotID,        /* the slot's ID */
		CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		CK_VOID_PTR           pApplication,  /* passed to callback */
		CK_NOTIFY             Notify,        /* callback function */
		CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
	);

	CK_RV CloseSession
	(
		CK_SESSION_HANDLE hSession  /* the session's handle */
	);

	CK_RV CloseAllSessions
	(
		CK_SLOT_ID     slotID  /* the token's slot */
	);

	CK_RV GetSessionInfo
	(
		CK_SESSION_HANDLE   hSession,  /* the session's handle */
		CK_SESSION_INFO_PTR pInfo      /* receives session info */
	);

	CK_RV Login
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_USER_TYPE      userType,  /* the user type */
		CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
		CK_ULONG          ulPinLen   /* the length of the PIN */
	);

	/* Object management */

	CK_RV GetAttributeValue
	(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_OBJECT_HANDLE  hObject,    /* the object's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	CK_RV SetAttributeValue
	(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_OBJECT_HANDLE  hObject,    /* the object's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	CK_RV FindObjectsInit
	(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
		CK_ULONG          ulCount     /* attributes in search template */
	);

	CK_RV FindObjects
	(
		CK_SESSION_HANDLE    hSession,          /* session's handle */
		CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
		CK_ULONG             ulMaxObjectCount,  /* max handles to get */
		CK_ULONG_PTR         pulObjectCount     /* actual # returned */
	);

	CK_RV FindObjectsFinal
	(
		CK_SESSION_HANDLE hSession  /* the session's handle */
	);

	/* Message digesting */

	CK_RV DigestInit
	(
		CK_SESSION_HANDLE hSession,   /* the session's handle */
		CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
	);


	CK_RV Digest
	(
		CK_SESSION_HANDLE hSession,     /* the session's handle */
		CK_BYTE_PTR       pData,        /* data to be digested */
		CK_ULONG          ulDataLen,    /* bytes of data to digest */
		CK_BYTE_PTR       pDigest,      /* gets the message digest */
		CK_ULONG_PTR      pulDigestLen  /* gets digest length */
	);

	CK_RV DigestUpdate
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* data to be digested */
		CK_ULONG          ulPartLen  /* bytes of data to be digested */
	);

	CK_RV DigestKey
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_OBJECT_HANDLE  hKey       /* secret key to digest */
	);

	CK_RV DigestFinal
	(
		CK_SESSION_HANDLE hSession,     /* the session's handle */
		CK_BYTE_PTR       pDigest,      /* gets the message digest */
		CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
	);

	/* Signing and MACing */

	CK_RV SignInit(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of signature key */
	);

	CK_RV Sign(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pData,           /* the data to sign */
		CK_ULONG          ulDataLen,       /* count of bytes to sign */
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	);

	CK_RV SignUpdate(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* the data to sign */
		CK_ULONG          ulPartLen  /* count of bytes to sign */
	);

	CK_RV SignFinal(
		CK_SESSION_HANDLE hSession,        /* the session's handle */
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
	);

	CK_RV VerifyInit
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
		CK_OBJECT_HANDLE  hKey         /* verification key */
	);

	CK_RV Verify
	(
		CK_SESSION_HANDLE hSession,       /* the session's handle */
		CK_BYTE_PTR       pData,          /* signed data */
		CK_ULONG          ulDataLen,      /* length of signed data */
		CK_BYTE_PTR       pSignature,     /* signature */
		CK_ULONG          ulSignatureLen  /* signature length*/
	);

	CK_RV VerifyUpdate
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_BYTE_PTR       pPart,     /* signed data */
		CK_ULONG          ulPartLen  /* length of signed data */
	);

	CK_RV VerifyFinal
	(
		CK_SESSION_HANDLE hSession,       /* the session's handle */
		CK_BYTE_PTR       pSignature,     /* signature to verify */
		CK_ULONG          ulSignatureLen  /* signature length */
	);

	/* Encryption and decryption */

	CK_RV EncryptInit
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
	);

	CK_RV Encrypt
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pData,               /* the plaintext data */
		CK_ULONG          ulDataLen,           /* bytes of plaintext */
		CK_BYTE_PTR       pEncryptedData,      /* gets ciphertext */
		CK_ULONG_PTR      pulEncryptedDataLen  /* gets c-text size */
	);

	CK_RV EncryptUpdate
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pPart,              /* the plaintext data */
		CK_ULONG          ulPartLen,          /* plaintext data len */
		CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
		CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
	);

	CK_RV EncryptFinal
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
		CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
	);

	CK_RV DecryptInit
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
		CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
	);

	CK_RV Decrypt
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pEncryptedData,     /* ciphertext */
		CK_ULONG          ulEncryptedDataLen, /* ciphertext length */
		CK_BYTE_PTR       pData,              /* gets plaintext */
		CK_ULONG_PTR      pulDataLen          /* gets p-text size */
	);

	CK_RV DecryptUpdate
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
		CK_ULONG          ulEncryptedPartLen,  /* input length */
		CK_BYTE_PTR       pPart,               /* gets plaintext */
		CK_ULONG_PTR      pulPartLen           /* p-text size */
	);

	CK_RV DecryptFinal
	(
		CK_SESSION_HANDLE hSession,    /* the session's handle */
		CK_BYTE_PTR       pLastPart,      /* gets plaintext */
		CK_ULONG_PTR      pulLastPartLen  /* p-text size */
	);
protected:
	Scoped<Slot> getSlotBySession(CK_SESSION_HANDLE hSession);
	Scoped<Session> getSession(CK_SESSION_HANDLE hSession);

};
