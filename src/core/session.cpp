#include "../stdafx.h"
#include "session.h"
#include "objects/key.h"
#include "objects/public_key.h"
#include "object.h"

using namespace core;

static CK_ATTRIBUTE_PTR ATTRIBUTE_new()
{
    CK_ATTRIBUTE_PTR attr = (CK_ATTRIBUTE*)malloc(sizeof(CK_ATTRIBUTE));
    attr->type = 0;
    attr->pValue = NULL_PTR;
    attr->ulValueLen = 0;
    return attr;
}

static void ATTRIBUTE_free(CK_ATTRIBUTE_PTR attr)
{
    if (attr) {
        if (attr->pValue) {
            free(attr->pValue);
            attr->pValue = NULL;
        }
        free(attr);
        attr = NULL;
    }
}

static void ATTRIBUTE_set_value(CK_ATTRIBUTE* attr, CK_VOID_PTR pbValue, CK_ULONG ulValueLen)
{
    if (pbValue && ulValueLen) {
        attr->pValue = (CK_VOID_PTR)malloc(ulValueLen);
        memcpy(attr->pValue, pbValue, ulValueLen);
    }
}

static void ATTRIBUTE_copy(CK_ATTRIBUTE* attrDst, CK_ATTRIBUTE* attrSrc)
{
    attrDst->type = attrSrc->type;
    attrDst->ulValueLen = attrSrc->ulValueLen;
    ATTRIBUTE_set_value(attrDst, attrSrc->pValue, attrSrc->ulValueLen);
}

Session::Session()
{
    this->Handle = 0;
    this->ReadOnly = true;
    this->Application = NULL_PTR;
    this->Notify = NULL_PTR;

    this->find.active = false;
    this->find.pTemplate = NULL;
    this->find.ulTemplateSize = 0;
    this->find.index = 0;
}

Session::~Session()
{
}

CK_RV Session::InitPIN
(
    CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
    CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV core::Session::Open
(
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    try {
        if (phSession == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phSession is NULL");
        }
        // the CKF_SERIAL_SESSION bit must always be set
        if (!(flags & CKF_SERIAL_SESSION)) {
            // if a call to C_OpenSession does not have this bit set, 
            // the call should return unsuccessfully with the error code CKR_SESSION_PARALLEL_NOT_SUPPORTED
            THROW_PKCS11_EXCEPTION(CKR_SESSION_PARALLEL_NOT_SUPPORTED, "the CKF_SERIAL_SESSION bit must always be set");
        }

        this->ReadOnly = !!(flags & CKF_RW_SESSION);
        this->Application = pApplication;
        this->Notify = Notify;
        this->Handle = reinterpret_cast<CK_SESSION_HANDLE>(this);
        *phSession = this->Handle;

        // Info
        this->Flags = flags;

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV core::Session::Close()
{
    return CKR_OK;
}

CK_RV core::Session::GetInfo
(
    CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
    CHECK_ARGUMENT_NULL(pInfo);

    pInfo->slotID = this->SlotID;
    pInfo->flags = this->Flags;
    pInfo->state = 0;
    pInfo->ulDeviceError = 0;

    return CKR_OK;
}

CK_RV core::Session::Login
(
    CK_USER_TYPE      userType,  /* the user type */
    CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
    CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
    switch (userType) {
    case CKU_USER:
    case CKU_SO:
    case CKU_CONTEXT_SPECIFIC:
        break;
    default:
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::GetAttributeValue
(
    CK_OBJECT_HANDLE  hObject,    /* the object's handle */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        Scoped<Object> object = this->GetObject(hObject);

        if (!object) {
            return CKR_OBJECT_HANDLE_INVALID;
        }
        if (pTemplate != NULL_PTR) {
            object->GetValues(pTemplate, ulCount);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Session::SetAttributeValue
(
    CK_OBJECT_HANDLE  hObject,    /* the object's handle */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        Scoped<Object> object = this->GetObject(hObject);

        if (!object) {
            return CKR_OBJECT_HANDLE_INVALID;
        }

        if (pTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pTemplate is NULL");
        }

        object->SetValues(pTemplate, ulCount);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject) {
    THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, "Function is not implemented");
}

CK_RV Session::FindObjectsInit
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
    CK_ULONG          ulCount     /* attributes in search template */
)
{
    if (this->find.active) {
        return CKR_OPERATION_ACTIVE;
    }
    this->find.active = true;
    // copy template
    this->find.pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCount);
    for (int i = 0; i < ulCount; i++) {
        this->find.pTemplate[i];
        // TODO: Maybe it would be better to use pointers without copying data
        ATTRIBUTE_copy(&this->find.pTemplate[i], &pTemplate[i]);
    }
    this->find.ulTemplateSize = ulCount;
    this->find.index = 0;

    return CKR_OK;
}

CK_RV Session::FindObjects
(
    CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
    CK_ULONG             ulMaxObjectCount,  /* max handles to get */
    CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
    try {
        if (!this->find.active) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }
        if (phObject == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phObject");
        }
        if (pulObjectCount == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pulObjectCount");
        }
        if (ulMaxObjectCount < 0) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "ulMaxObjectCount must be more than 0");
        }

        *pulObjectCount = 0;
        CK_RV res;
        for (this->find.index; this->find.index < objects.count() && *pulObjectCount < ulMaxObjectCount; this->find.index++) {
            Scoped<Object> obj = this->objects.items(this->find.index);
            size_t i = 0;
            for (i; i < this->find.ulTemplateSize; i++) {
                CK_ATTRIBUTE_PTR findAttr = &this->find.pTemplate[i];
                Buffer attrValue;
                CK_ATTRIBUTE attr = { findAttr->type , NULL_PTR, 0 };
                res = obj->GetValues(&attr, 1);
                if (res != CKR_OK) {
                    break;
                }
                if (attr.ulValueLen != findAttr->ulValueLen) {
                    break;
                }
                attrValue.resize(attr.ulValueLen);
                attr.pValue = attrValue.data();
                res = obj->GetValues(&attr, 1);
                if (res != CKR_OK) {
                    break;
                }
                if (memcmp(findAttr->pValue, attr.pValue, findAttr->ulValueLen)) {
                    break;
                }
            }
            if (i != this->find.ulTemplateSize) {
                continue;
            }

            phObject[*pulObjectCount] = obj->handle;
            *pulObjectCount += 1;
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::FindObjectsFinal()
{
    if (!this->find.active) {
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    // destroy Template
    if (this->find.pTemplate) {
        for (int i = 0; i < this->find.ulTemplateSize; i++) {
            if (this->find.pTemplate[i].pValue) {
                free(this->find.pTemplate[i].pValue);
            }
        }
        free(this->find.pTemplate);
    }
    this->find.pTemplate = NULL;
    this->find.ulTemplateSize = 0;
    this->find.active = false;
    this->find.index = 0;

    return CKR_OK;
}

void Session::CheckMechanismType(CK_MECHANISM_TYPE mechanism, CK_ULONG usage)
{
    CK_ULONG ulMechanismCount;
    CK_RV res = C_GetMechanismList(this->SlotID, NULL_PTR, &ulMechanismCount);
    if (res != CKR_OK) {
        THROW_PKCS11_EXCEPTION(res, "Cannot get mechanism list");
    }

    bool found = false;
    CK_MECHANISM_TYPE_PTR mechanisms = static_cast<CK_MECHANISM_TYPE_PTR>(malloc(ulMechanismCount * sizeof(CK_MECHANISM_TYPE)));
    res = C_GetMechanismList(this->SlotID, mechanisms, &ulMechanismCount);
    if (res != CKR_OK) {
        free(mechanisms);
        THROW_PKCS11_EXCEPTION(res, "Cannot get mechanism list");
    }
    for (size_t i = 0; i < ulMechanismCount; i++) {
        if (mechanisms[i] == mechanism) {
            CK_MECHANISM_INFO info;
            // check mechanism usage
            res = C_GetMechanismInfo(this->SlotID, mechanism, &info);
            if (res != CKR_OK) {
                free(mechanisms);
                THROW_PKCS11_EXCEPTION(res, "Cannot get mechanism info");
            }
            else {
                if (info.flags & usage) {
                    found = true;
                }
                break;
            }
        }
    }
    free(mechanisms);

    if (!found) {
        THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Mechanism not found");
    }
}

CK_RV Session::VerifyInit(
    CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
    CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_VERIFY);
        if (hKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "hKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV Session::SignInit(
    CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_VERIFY);
        if (hKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "hKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

/* Encryption and decryption */

CK_RV Session::EncryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_ENCRYPT);
        if (hKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "hKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV Session::DecryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
    try {

        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_DECRYPT);
        if (hKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "hKey is NULL");
        }
        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV Session::GenerateKey
(
    CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
    CK_ULONG             ulCount,     /* # of attrs in template */
    CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_GENERATE);
        if (pTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pTemplate is NULL");
        }
        if (phKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV Session::GenerateKeyPair
(
    CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
    CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
    CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
    CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
    CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
    CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
    CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_GENERATE);
        if (pPrivateKeyTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pPrivateKeyTemplate is NULL");
        }
        if (pPublicKeyTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pPublicKeyTemplate is NULL");
        }
        if (phPublicKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phPublicKey is NULL");
        }
        if (phPrivateKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phPrivateKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

Scoped<Object> Session::GetObject(
    CK_OBJECT_HANDLE hObject
)
{
    try {
        for (int i = 0; i < objects.count(); i++) {
            auto object = objects.items(i);
            if (object->handle == hObject) {
                return object;
            }
        }
        THROW_PKCS11_EXCEPTION(CKR_OBJECT_HANDLE_INVALID, "Cannot get Object by Handle");
    }
    CATCH_EXCEPTION
}

CK_RV core::Session::SeedRandom(
    CK_BYTE_PTR       pSeed,     /* the seed material */
    CK_ULONG          ulSeedLen  /* length of seed material */
)
{
    try {
        if (pSeed == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pSeed is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

CK_RV core::Session::GenerateRandom(
    CK_BYTE_PTR       pRandomData,  /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    try {
        if (pRandomData == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pRandomData is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::DeriveKey
(
    CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
    CK_OBJECT_HANDLE     hBaseKey,          /* base key */
    CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
    CK_ULONG             ulAttributeCount,  /* template length */
    CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        CheckMechanismType(pMechanism->mechanism, CKF_DERIVE);
        if (hBaseKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "hBaseKey is NULL");
        }
        if (pTemplate == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pTemplate is NULL");
        }
        if (phKey == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "phKey is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}
