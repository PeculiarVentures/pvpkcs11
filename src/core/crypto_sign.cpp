#include "crypto.h"

using namespace core;

CK_RV CryptoSign::Init
(
    CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
    Scoped<Object>    key          /* signature key */
)
{
    try {
        if (active) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (!(key && key.get())) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

/**
 * Sign
 */
CK_RV CryptoSign::Once(
    CK_BYTE_PTR       pData,           /* the data to sign */
    CK_ULONG          ulDataLen,       /* count of bytes to sign */
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    try {
        try {
            Update(pData, ulDataLen);
            Final(pSignature, pulSignatureLen);
        }
        catch (Scoped<core::Exception> e) {
            active = false;
            throw e;
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

/**
 * Verify
 */
CK_RV CryptoSign::Once(
    CK_BYTE_PTR       pData,           /* the data to sign */
    CK_ULONG          ulDataLen,       /* count of bytes to sign */
    CK_BYTE_PTR       pSignature,      /* signature to verify */
    CK_ULONG          ulSignatureLen   /* signature length */
)
{
    try {
        try {
            Update(pData, ulDataLen);
            Final(pSignature, ulSignatureLen);
        }
        catch (Scoped<core::Exception> e) {
            active = false;
            throw e;
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoSign::Update(
    CK_BYTE_PTR       pPart,     /* the data to sign/verify */
    CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
)
{
    try {
        if (!active) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }
        if (pPart == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pPart is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoSign::Final(
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    try {
        if (!active) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoSign::Final(
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    try {
        if (!active) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }
        if (pSignature == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pSignature is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

bool CryptoSign::IsActive() {
    return active;
}