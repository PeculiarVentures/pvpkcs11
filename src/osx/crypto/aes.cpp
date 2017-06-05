#include "../crypto.h"

using namespace osx;

osx::CryptoAesEncrypt::CryptoAesEncrypt(
    CK_BBOOL        type
) :
    core::CryptoEncrypt(type)
{
}

CK_RV osx::CryptoAesEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    key
)
{
    try {
        core::CryptoEncrypt::Init(pMechanism, key);
        
        AesKey* aesKey = dynamic_cast<AesKey*>(key.get());
        
        if (!aesKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not AES");
        }
        
        CCMode mode;
        CCPadding padding = ccNoPadding;
        switch (pMechanism->mechanism) {
            case CKM_AES_CBC_PAD:
                padding = ccPKCS7Padding;
            case CKM_AES_CBC:
                mode = kCCModeCBC;
                // IV
                if (pMechanism->pParameter == NULL_PTR) {
                    THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
                }
                if (pMechanism->ulParameterLen != 16) {
                    THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "AES-CBC IV must be 16 bytes");
                }
                break;
            case CKM_AES_ECB:
                mode = kCCModeECB;
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        auto keyData = key->ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();
        CCCryptorStatus status = CCCryptorCreateWithMode(
            this->type ? kCCDecrypt : kCCEncrypt,
            mode,
            kCCAlgorithmAES,
            padding,
            pMechanism->mechanism == CKM_AES_ECB ? NULL : pMechanism->pParameter,
            keyData->data(),
            keyData->size(),
            NULL, 0, 0, 0, &cryptor
        );

        if (status) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Error on CCCryptorCreateWithMode");
        }
        
        active = true;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}


CK_RV osx::CryptoAesEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
    try {
        core::CryptoEncrypt::Update(pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
        
        CCCryptorStatus status = CCCryptorUpdate(cryptor, pPart, ulPartLen, pEncryptedPart, pEncryptedPart ? *pulEncryptedPartLen : 0, pulEncryptedPartLen);
        
        if (status) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Error on CCCryptorUpdate");
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::CryptoAesEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
    try {
        core::CryptoEncrypt::Final(pLastEncryptedPart, pulLastEncryptedPartLen);
        
        CCCryptorStatus status = CCCryptorFinal(cryptor, pLastEncryptedPart, pLastEncryptedPart ? *pulLastEncryptedPartLen : 0, pulLastEncryptedPartLen);
        if (status) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Error on CCCryptorFinal");
        }
        CFRelease(cryptor);
        cryptor = NULL;
        
        active = false;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

