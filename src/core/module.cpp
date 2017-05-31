#include "../stdafx.h"
#include "module.h"

using namespace core;

#define CHECK_INITIALIZED()						\
	if (!this->initialized) {					\
		THROW_PKCS11_EXCEPTION(CKR_CRYPTOKI_NOT_INITIALIZED, "Module is not initialized");	\
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

Module::Module()
{
    this->initialized = false;
}

CK_RV Module::Initialize(
    CK_VOID_PTR   pInitArgs
)
{
    if (this->initialized) {
        return CKR_CRYPTOKI_ALREADY_INITIALIZED;
    }
    this->initialized = true;
    return CKR_OK;
}

CK_RV Module::Finalize(
    CK_VOID_PTR pReserved
)
{
    try {
        CHECK_INITIALIZED();

        initialized = false;

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV Module::GetInfo(
    CK_INFO_PTR pInfo
)
{
    CHECK_INITIALIZED();
    CHECK_ARGUMENT_NULL(pInfo);

    pInfo->cryptokiVersion.major = CRYPTOKI_VERSION_MAJOR;
    pInfo->cryptokiVersion.minor = CRYPTOKI_VERSION_MINOR;
    pInfo->flags = 0;
    SET_STRING(pInfo->manufacturerID, "Module", 32);
    SET_STRING(pInfo->libraryDescription, "Windows CryptoAPI", 32);
    pInfo->libraryVersion.major = 0;
    pInfo->libraryVersion.minor = 1;

    return CKR_OK;
}

CK_RV Module::GetSlotList(
    CK_BBOOL       tokenPresent,  /* only slots with tokens? */
    CK_SLOT_ID_PTR pSlotList,     /* receives array of slot IDs */
    CK_ULONG_PTR   pulCount       /* receives number of slots */
)
{
    try {
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
    CATCH_EXCEPTION;
}

CK_RV Module::GetSlotInfo(
    CK_SLOT_ID       slotID,  /* the ID of the slot */
    CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
    try {
        CHECK_INITIALIZED();

        auto slot = getSlot(slotID);

        return slot->GetSlotInfo(pInfo);
    }
    CATCH_EXCEPTION;


}

CK_RV Module::GetTokenInfo
(
    CK_SLOT_ID        slotID,  /* ID of the token's slot */
    CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
    try {
        CHECK_INITIALIZED();

        auto slot = getSlot(slotID);

        return slot->GetTokenInfo(pInfo);
    }
    CATCH_EXCEPTION;
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

    return CKR_FUNCTION_NOT_SUPPORTED;
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

    if (!(slot && slot.get())) {
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
    THROW_PKCS11_EXCEPTION(CKR_SESSION_HANDLE_INVALID, "Session handle invalid");
}

Scoped<Session> Module::getSession(CK_SESSION_HANDLE hSession)
{
    try {
        Scoped<Slot> slot = this->getSlotBySession(hSession);
        if (slot) {
            Scoped<Session> session = slot->getSession(hSession);
            return session;
        }

        THROW_PKCS11_EXCEPTION(CKR_SESSION_HANDLE_INVALID, "Cannot get Session");
    }
    CATCH_EXCEPTION;
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

    return session->GetInfo(pInfo);
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
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        if (pMechanism == NULL) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        session->CheckMechanismType(pMechanism->mechanism, CKF_DIGEST);

        return session->digest->Init(pMechanism);
    }
    CATCH_EXCEPTION;
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
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->digest->Once(
            pData,
            ulDataLen,
            pDigest,
            pulDigestLen
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::DigestUpdate
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pPart,     /* data to be digested */
    CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->digest->Update(
            pPart,
            ulPartLen
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::DigestKey
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);
        auto object = session->GetObject(hKey);

        return session->digest->Key(
            object
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::DigestFinal
(
    CK_SESSION_HANDLE hSession,     /* the session's handle */
    CK_BYTE_PTR       pDigest,      /* gets the message digest */
    CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->digest->Final(
            pDigest,
            pulDigestLen
        );
    }
    CATCH_EXCEPTION;
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->sign->Once(
            pData,
            ulDataLen,
            pSignature,
            pulSignatureLen
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::SignUpdate(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pPart,     /* the data to sign */
    CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->sign->Update(pPart, ulPartLen);
    }
    CATCH_EXCEPTION
}

CK_RV Module::SignFinal(
    CK_SESSION_HANDLE hSession,        /* the session's handle */
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->sign->Final(pSignature, pulSignatureLen);
    }
    CATCH_EXCEPTION
}

CK_RV Module::VerifyInit
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
    CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->VerifyInit(pMechanism, hKey);
    }
    CATCH_EXCEPTION
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->verify->Once(
            pData,
            ulDataLen,
            pSignature,
            ulSignatureLen
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::VerifyUpdate
(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pPart,     /* signed data */
    CK_ULONG          ulPartLen  /* length of signed data */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->verify->Update(pPart, ulPartLen);
    }
    CATCH_EXCEPTION
}

CK_RV Module::VerifyFinal
(
    CK_SESSION_HANDLE hSession,       /* the session's handle */
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->verify->Final(pSignature, ulSignatureLen);
    }
    CATCH_EXCEPTION
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->encrypt->Once(
            pData,
            ulDataLen,
            pEncryptedData,
            pulEncryptedDataLen
        );
    }
    CATCH_EXCEPTION
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->encrypt->Update(
            pPart,
            ulPartLen,
            pEncryptedPart,
            pulEncryptedPartLen
        );
    }
    CATCH_EXCEPTION
}

CK_RV Module::EncryptFinal
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
    CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->encrypt->Final(
            pLastEncryptedPart,
            pulLastEncryptedPartLen
        );
    }
    CATCH_EXCEPTION
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->decrypt->Once(
            pEncryptedData,
            ulEncryptedDataLen,
            pData,
            pulDataLen
        );
    }
    CATCH_EXCEPTION
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
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->decrypt->Update(
            pEncryptedPart,
            ulEncryptedPartLen,
            pPart,
            pulPartLen
        );
    }
    CATCH_EXCEPTION
}

CK_RV Module::DecryptFinal
(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_BYTE_PTR       pLastPart,      /* gets plaintext */
    CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
    try {
        CHECK_INITIALIZED();
        GET_SESSION(hSession);

        return session->decrypt->Final(
            pLastPart,
            pulLastPartLen
        );
    }
    CATCH_EXCEPTION
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

CK_RV Module::GenerateKeyPair
(
    CK_SESSION_HANDLE    hSession,                    /* session handle */
    CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
    CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
    CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
    CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
    CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
    CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
    CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
)
{
    CHECK_INITIALIZED();
    GET_SESSION(hSession);

    return session->GenerateKeyPair(
        pMechanism,
        pPublicKeyTemplate,
        ulPublicKeyAttributeCount,
        pPrivateKeyTemplate,
        ulPrivateKeyAttributeCount,
        phPublicKey,
        phPrivateKey
    );
}

Scoped<Slot> Module::getSlot(
    CK_SLOT_ID slotID
)
{
    try {
        if (!(slotID >= 0 && slotID < slots.count())) {
            THROW_PKCS11_EXCEPTION(CKR_SLOT_ID_INVALID, "Cannot get Slot by ID");
        }
        return slots.items(slotID);
    }
    CATCH_EXCEPTION;
}

CK_RV Module::SeedRandom(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_BYTE_PTR       pSeed,     /* the seed material */
    CK_ULONG          ulSeedLen  /* length of seed material */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->SeedRandom(pSeed, ulSeedLen);
    }
    CATCH_EXCEPTION;
}

/* C_GenerateRandom generates random data. */
CK_RV Module::GenerateRandom(
    CK_SESSION_HANDLE hSession,    /* the session's handle */
    CK_BYTE_PTR       pRandomData,  /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->GenerateRandom(pRandomData, ulRandomLen);
    }
    CATCH_EXCEPTION;
}

CK_RV Module::DeriveKey
(
    CK_SESSION_HANDLE    hSession,          /* session handle */
    CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
    CK_OBJECT_HANDLE     hBaseKey,          /* base key */
    CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
    CK_ULONG             ulAttributeCount,  /* template length */
    CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        return session->DeriveKey(
            pMechanism,
            hBaseKey,
            pTemplate,
            ulAttributeCount,
            phKey
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Module::CreateObject
(
    CK_SESSION_HANDLE       hSession,    /* the session's handle */
    CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
    CK_ULONG                ulCount,     /* attributes in template */
    CK_OBJECT_HANDLE_PTR    phObject     /* gets new object's handle. */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        if (pTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pTemplate is NULL");
        }

        if (phObject == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phObject is NULL");
        }

        auto object = session->CreateObject(
            pTemplate,
            ulCount
        );

        if (!object) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object wasn't created");
        }

        session->objects.add(object);

        *phObject = object->handle;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Module::CopyObject
(
    CK_SESSION_HANDLE    hSession,    /* the session's handle */
    CK_OBJECT_HANDLE     hObject,     /* the object's handle */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
    CK_ULONG             ulCount,     /* attributes in template */
    CK_OBJECT_HANDLE_PTR phNewObject  /* receives handle of copy */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);

        if (pTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pTemplate is NULL");
        }

        if (phNewObject == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phObject is NULL");
        }

        auto object = session->GetObject(hObject);

        auto newObject = session->CopyObject(
            object,
            pTemplate,
            ulCount
        );

        if (!newObject) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object wasn't created");
        }

        session->objects.add(newObject);

        *phNewObject = newObject->handle;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Module::DestroyObject(
    CK_SESSION_HANDLE hSession,  /* the session's handle */
    CK_OBJECT_HANDLE  hObject    /* the object's handle */
)
{
    try {
        CHECK_INITIALIZED();

        auto session = getSession(hSession);
        auto object = session->GetObject(hObject);

        object->Destroy();

        session->objects.remove(object);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}