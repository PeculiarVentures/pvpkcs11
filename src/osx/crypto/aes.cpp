#include "../crypto.h"

#include "CommonCryptoSPI.h"

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
        
        Scoped<Buffer> keyData = key->ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();
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
        CCCryptorRelease(cryptor);
        cryptor = NULL;
        
        active = false;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

// AES-GCM

CryptoAesGCMEncrypt::CryptoAesGCMEncrypt
(
 CK_BBOOL type
 ) :
core::CryptoEncrypt(type)
{}

CK_RV CryptoAesGCMEncrypt::Init
(
 CK_MECHANISM_PTR        pMechanism,
 Scoped<core::Object>    key
 )
{
    try {
        core::CryptoEncrypt::Init(pMechanism,
                                  key);
        
        if (!(key && key.get())) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
        }
        this->key = dynamic_cast<AesKey*>(key.get());
        if (!this->key) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key must be AES");
        }
        
        if (pMechanism->mechanism != CKM_AES_GCM) {
            THROW_PKCS11_MECHANISM_INVALID();
        }
        
        // params
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }
        CK_AES_GCM_PARAMS_PTR params = static_cast<CK_AES_GCM_PARAMS_PTR>(pMechanism->pParameter);
        if (!params) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "Cannot get CK_AES_GCM_PARAMS");
        }
        
        // IV
        iv = Scoped<std::string>(new std::string((char*)params->pIv, params->ulIvLen));
        
        // AAD
        aad = Scoped<std::string>(new std::string(""));
        if (params->ulAADLen) {
            aad = Scoped<std::string>(new std::string((char*)params->pAAD, params->ulAADLen));
        }
        
        // tagLength
        tagLength = params->ulTagBits >> 3;
        
        active = true;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesGCMEncrypt::Once
(
 CK_BYTE_PTR       pData,
 CK_ULONG          ulDataLen,
 CK_BYTE_PTR       pEncryptedData,
 CK_ULONG_PTR      pulEncryptedDataLen
 )
{
    try {
        OSStatus status;

        if (type == CRYPTO_ENCRYPT) {
            CK_ULONG ulOutLen = ulDataLen;
            
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulOutLen + tagLength;
            }
            else if (*pulEncryptedDataLen < ulOutLen + tagLength) {
                *pulEncryptedDataLen = ulOutLen + tagLength;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                Scoped<Buffer> keyData = key->ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();
                status = CCCryptorGCM(kCCEncrypt,
                                      kCCAlgorithmAES,
                                      keyData->data(), keyData->size(),
                                      iv->c_str(), iv->length(),
                                      aad->c_str(), aad->length(),
                                      pData, ulDataLen,
                                      pEncryptedData,
                                      pEncryptedData + ulOutLen, &tagLength);
                *pulEncryptedDataLen = ulOutLen + tagLength;
                active = false;
                if (status) {
                    THROW_EXCEPTION("Error on CCCryptorGCM");
                }
            }
        }
        else {
            CK_ULONG ulOutLen = ulDataLen - tagLength;
            
            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulOutLen;
            }
            else if (*pulEncryptedDataLen < ulOutLen) {
                *pulEncryptedDataLen = ulOutLen;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                Scoped<Buffer> keyData = key->ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();
                Buffer tag(tagLength);
                status = CCCryptorGCM(kCCDecrypt,
                                      kCCAlgorithmAES,
                                      keyData->data(), keyData->size(),
                                      iv->c_str(), iv->length(),
                                      aad->c_str(), aad->length(),
                                      pData, ulDataLen,
                                      pEncryptedData,
                                      tag.data(), &tagLength);
                *pulEncryptedDataLen = ulOutLen;
                active = false;
                if (status) {
                    THROW_EXCEPTION("Error on CCCryptorGCM");
                }
            }
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesGCMEncrypt::Update
(
 CK_BYTE_PTR       pPart,
 CK_ULONG          ulPartLen,
 CK_BYTE_PTR       pEncryptedPart,
 CK_ULONG_PTR      pulEncryptedPartLen
 )
{
    THROW_PKCS11_MECHANISM_INVALID();
}

CK_RV CryptoAesGCMEncrypt::Final
(
 CK_BYTE_PTR       pLastEncryptedPart,
 CK_ULONG_PTR      pulLastEncryptedPartLen
 )
{
    THROW_PKCS11_MECHANISM_INVALID();
}

