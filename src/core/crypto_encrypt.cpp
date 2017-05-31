#include "crypto.h"

using namespace core;

CryptoEncrypt::CryptoEncrypt(
    CK_BBOOL type
) :
    active(false),
    type(type)
{

}

CK_RV CryptoEncrypt::Init
(
    CK_MECHANISM_PTR  pMechanism,
    Scoped<Object>    hKey
)
{
    try {
        if (IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

CK_RV CryptoEncrypt::Once
(
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen
)
{
    try {
        CK_ULONG ulPaddingLen = *pulEncryptedDataLen;
        Update(pData, ulDataLen, pEncryptedData, &ulPaddingLen);
        CK_BYTE_PTR pPadding = pEncryptedData + ulPaddingLen;
        *pulEncryptedDataLen = *pulEncryptedDataLen - ulPaddingLen;
        Final(pPadding, pulEncryptedDataLen);
        *pulEncryptedDataLen += ulPaddingLen;
        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV CryptoEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
    try {
        if (!IsActive()) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }
        if (pPart == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pPart is NULL");
        }
        if (pEncryptedPart == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pEncryptedPart is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

CK_RV CryptoEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
    try {
        if (!IsActive()) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }

        if (pLastEncryptedPart == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pLastEncryptedPart is NULL");
        }

        return CKR_FUNCTION_NOT_SUPPORTED;
    }
    CATCH_EXCEPTION;
}

bool CryptoEncrypt::IsActive()
{
    return active;
}