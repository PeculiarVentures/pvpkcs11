#include "../crypto.h"

#include "../rsa.h"

using namespace osx;

osx::RsaPKCS1Sign::RsaPKCS1Sign(CK_BBOOL type) :
core::CryptoSign(type)
{
    LOGGER_FUNCTION_BEGIN;
}

CK_RV osx::RsaPKCS1Sign::Init
(
 CK_MECHANISM_PTR        pMechanism,
 Scoped<core::Object>    key
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::CryptoSign::Init(pMechanism, key);
        
        CK_MECHANISM digestMechanism;
        digestMechanism.pParameter = NULL;
        digestMechanism.ulParameterLen = 0;
        switch (pMechanism->mechanism) {
            case CKM_SHA1_RSA_PKCS:
                digestMechanism.mechanism = CKM_SHA_1;
                break;
            case CKM_SHA256_RSA_PKCS:
                digestMechanism.mechanism = CKM_SHA256;
                break;
            case CKM_SHA384_RSA_PKCS:
                digestMechanism.mechanism = CKM_SHA384;
                break;
            case CKM_SHA512_RSA_PKCS:
                digestMechanism.mechanism = CKM_SHA512;
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Wrong Mechanism in use");
        }
        
        digest.Init(&digestMechanism);
        
        if (type == CRYPTO_SIGN) {
            if (!dynamic_cast<RsaPrivateKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA private key");
            }
        }
        else {
            if (!dynamic_cast<RsaPublicKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA public key");
            }
        }
        
        this->key = dynamic_cast<Key*>(key.get());
        if (!this->key) {
            THROW_EXCEPTION("Cannot convert to Key");
        }
        
        active = true;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPKCS1Sign::Update
(
 CK_BYTE_PTR       pPart,
 CK_ULONG          ulPartLen
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::CryptoSign::Update(pPart, ulPartLen);
        
        digest.Update(pPart, ulPartLen);
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPKCS1Sign::Final
(
 CK_BYTE_PTR       pSignature,
 CK_ULONG_PTR      pulSignatureLen
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        CryptoSign::Final(pSignature, pulSignatureLen);
        
        // get size of signature
        CK_ULONG ulSignatureLen = 128;
        SecKeyAlgorithm keyAlgorithm;
        switch (digest.mechType) {
            case CKM_SHA_1:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
                break;
            case CKM_SHA256:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
                break;
            case CKM_SHA384:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
                break;
            case CKM_SHA512:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
                break;
            default:
                THROW_EXCEPTION("Wrong digest mechanism type");
        }
        
        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            CK_BYTE hash[256] = {0};
            CK_ULONG hashLen = 256;
            digest.Final(hash, &hashLen);
            
            CFRef<CFDataRef> cfHash = CFDataCreate(NULL, hash, hashLen);
            
            SecKeyRef secKey = key->Get();
            CFRef<CFDataRef> signature = SecKeyCreateSignature(secKey,
                                                               keyAlgorithm,
                                                               *cfHash,
                                                               NULL);
            
            active = false;
            
            if (signature.IsEmpty()) {
                THROW_EXCEPTION("Error on SecKeyCreateSignature");
            }
            
            *pulSignatureLen = CFDataGetLength(*signature);
            memcpy(pSignature, (CK_BYTE_PTR)CFDataGetBytePtr(*signature), *pulSignatureLen);
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPKCS1Sign::Final
(
 CK_BYTE_PTR       pSignature,
 CK_ULONG          ulSignatureLen
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        CryptoSign::Final(pSignature, ulSignatureLen);
        
        SecKeyAlgorithm keyAlgorithm;
        switch (digest.mechType) {
            case CKM_SHA_1:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA1;
                break;
            case CKM_SHA256:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA256;
                break;
            case CKM_SHA384:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA384;
                break;
            case CKM_SHA512:
                keyAlgorithm = kSecKeyAlgorithmRSASignatureDigestPKCS1v15SHA512;
                break;
            default:
                THROW_EXCEPTION("Wrong digest mechanism type");
        }
        
        CK_BYTE hash[256] = {0};
        CK_ULONG hashLen = 256;
        digest.Final(hash, &hashLen);
        
        CFRef<CFDataRef> cfHash = CFDataCreate(NULL, hash, hashLen);
        CFRef<CFDataRef> cfSignature = CFDataCreate(NULL, pSignature, ulSignatureLen);
        
        SecKeyRef secKey = key->Get();
        Boolean ok = SecKeyVerifySignature(
                                           secKey,
                                           keyAlgorithm,
                                           *cfHash,
                                           *cfSignature,
                                           NULL);
        
        active = false;
        
        return ok ? CKR_OK : CKR_SIGNATURE_INVALID;
    }
    CATCH_EXCEPTION
}
