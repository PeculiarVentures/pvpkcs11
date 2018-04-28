#include "../crypto.h"

#include "../ec.h"

#include <Security/SecAsn1Types.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Coder.h>

using namespace osx;

typedef struct {
    SecAsn1Item x;
    SecAsn1Item y;
} ASN1_EC_SIGNATURE;

const SecAsn1Template kEcSignatureTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_SIGNATURE)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_EC_SIGNATURE, x)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_EC_SIGNATURE, y)},
    {0},
};

Scoped<Buffer> ConvertSignatureToWebcrypto(CFDataRef data, CK_ULONG size) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        
        ASN1_EC_SIGNATURE asn1Signature;
        if (SecAsn1Decode(coder, CFDataGetBytePtr(data), CFDataGetLength(data), kEcSignatureTemplate, &asn1Signature)){
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Cannot decode EC signature");
        }

        // X
        Scoped<Buffer> x(new Buffer(size));
        memset(x->data(), 0, x->size());
        memcpy(x->data() + (size - asn1Signature.x.Length), asn1Signature.x.Data, asn1Signature.x.Length);
        
        // Y
        Scoped<Buffer> y(new Buffer(size));
        memset(y->data(), 0, y->size());
        memcpy(y->data() + (size - asn1Signature.y.Length), asn1Signature.y.Data, asn1Signature.y.Length);
        
        // result
        Scoped<Buffer> res(new Buffer(size * 2));
        memcpy(res->data(), x->data(), x->size());
        memcpy(res->data() + x->size(), y->data(), y->size());
        
        SecAsn1CoderRelease(coder);
        
        return res;
    }
    CATCH_EXCEPTION
}

CK_ULONG GetIntegerPaddingSize(CK_BYTE_PTR data, CK_ULONG dataLen) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        for (int i = 0; i < dataLen; i++) {
            if (data[i] != 0) {
                return i;
            }
        }
        return 0;
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> ConvertSignatureFromWebcrypto(CFDataRef data) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        
        CK_BYTE_PTR x = (CK_BYTE_PTR)CFDataGetBytePtr(data);
        CK_ULONG size = CFDataGetLength(data) / 2;
        CK_ULONG xPaddingSize = GetIntegerPaddingSize(x, size);

        CK_BYTE_PTR y = x + size;
        CK_ULONG yPaddingSize = GetIntegerPaddingSize(y, size);
        
        ASN1_EC_SIGNATURE asn1Signature;
        asn1Signature.x.Data = x + xPaddingSize;
        asn1Signature.x.Length = size - xPaddingSize;
        asn1Signature.y.Data = y + yPaddingSize;
        asn1Signature.y.Length = size - yPaddingSize;
        
        SecAsn1Item derSignature;
        if (SecAsn1EncodeItem(coder, &asn1Signature, kEcSignatureTemplate, &derSignature)){
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Cannot decode EC signature");
        }
        
        Scoped<Buffer> res(new Buffer(derSignature.Length));
        memcpy(res->data(), derSignature.Data, derSignature.Length);
        
        SecAsn1CoderRelease(coder);
        
        return res;
    }
    CATCH_EXCEPTION
}


osx::EcDsaSign::EcDsaSign(CK_BBOOL type) :
core::CryptoSign(type)
{
}

CK_RV osx::EcDsaSign::Init
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
            case CKM_ECDSA_SHA1:
                digestMechanism.mechanism = CKM_SHA_1;
                break;
            case CKM_ECDSA_SHA256:
                digestMechanism.mechanism = CKM_SHA256;
                break;
            case CKM_ECDSA_SHA384:
                digestMechanism.mechanism = CKM_SHA384;
                break;
            case CKM_ECDSA_SHA512:
                digestMechanism.mechanism = CKM_SHA512;
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Wrong Mechanism in use");
        }
        
        digest.Init(&digestMechanism);
        
        if (type == CRYPTO_SIGN) {
            if (!dynamic_cast<EcPrivateKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC private key");
            }
        }
        else {
            if (!dynamic_cast<EcPublicKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC public key");
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

CK_RV osx::EcDsaSign::Update
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

CK_RV osx::EcDsaSign::Final
(
 CK_BYTE_PTR       pSignature,
 CK_ULONG_PTR      pulSignatureLen
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        CryptoSign::Final(pSignature, pulSignatureLen);
        
        CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributesEx(key->Get());
        CFNumberRef cfKeySizeInBits = (CFNumberRef) CFDictionaryGetValue(*attrs, kSecAttrKeySizeInBits);
        if (!cfKeySizeInBits) {
            THROW_PARAM_REQUIRED_EXCEPTION("kSecAttrKeySizeInBits");
        }
        CK_ULONG keySizeInBits = 0;
        if (!CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt32Type, &keySizeInBits)) {
            THROW_EXCEPTION("Cannot convert CFNumberRef to CK_ULONG");
        }
        keySizeInBits = (keySizeInBits + 7) >> 3;
        
        // get size of signature
        CK_ULONG ulSignatureLen = keySizeInBits; // TODO: wrong size
        SecKeyAlgorithm keyAlgorithm;
        switch (digest.mechType) {
            case CKM_SHA_1:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA1;
                break;
            case CKM_SHA256:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
                break;
            case CKM_SHA384:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
                break;
            case CKM_SHA512:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
                break;
            default:
                THROW_EXCEPTION("Wron digest mechanism type");
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
            
            CFRef<CFErrorRef> cfError;
            CFRef<CFDataRef> signature = SecKeyCreateSignature(key->Get(),
                                                               keyAlgorithm,
                                                               *cfHash,
                                                               &cfError);
            
            active = false;
            
            if (!cfError.IsEmpty()) {
                CFRef<CFStringRef> errorMessage = CFErrorCopyDescription(*cfError);
                THROW_EXCEPTION("Error on SecKeyCreateSignature. %s",
                                CFStringGetCStringPtr(*errorMessage, kCFStringEncodingUTF8));
            }
            
            Scoped<Buffer> wcSignature = ConvertSignatureToWebcrypto(*signature, keySizeInBits);
            
            *pulSignatureLen = wcSignature->size();
            memcpy(pSignature, wcSignature->data(), wcSignature->size());
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::EcDsaSign::Final
(
 CK_BYTE_PTR       pSignature,
 CK_ULONG          ulSignatureLen
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        CryptoSign::Final(pSignature, ulSignatureLen);
        
        // check signature size
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(key->Get());
        if (!&cfAttributes) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(*cfAttributes, kSecAttrKeySizeInBits);
        if (!cfKeySizeInBits) {
            THROW_EXCEPTION("Cannot get size of key");
        }
        CK_ULONG keySizeInBits = 0;
        CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt64Type, &keySizeInBits);
        keySizeInBits = (keySizeInBits + 7) >> 3;
        if (ulSignatureLen != keySizeInBits * 2) {
            THROW_PKCS11_EXCEPTION(CKR_SIGNATURE_INVALID, "Signature has wrong size");
        }
        
        SecKeyAlgorithm keyAlgorithm;
        switch (digest.mechType) {
            case CKM_SHA_1:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA1;
                break;
            case CKM_SHA256:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA256;
                break;
            case CKM_SHA384:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA384;
                break;
            case CKM_SHA512:
                keyAlgorithm = kSecKeyAlgorithmECDSASignatureDigestX962SHA512;
                break;
            default:
                THROW_EXCEPTION("Wron digest mechanism type");
        }
        
        CK_BYTE hash[256] = {0};
        CK_ULONG hashLen = 256;
        digest.Final(hash, &hashLen);
        
        CFRef<CFDataRef> cfHash = CFDataCreate(NULL, hash, hashLen);
        CFRef<CFDataRef> cfWebcryptoSignature = CFDataCreate(NULL, pSignature, ulSignatureLen);
        Scoped<Buffer> derSignature = ConvertSignatureFromWebcrypto(*cfWebcryptoSignature);
        CFRef<CFDataRef> cfSignature = CFDataCreate(NULL, derSignature->data(), derSignature->size());
        
        Boolean ok = SecKeyVerifySignature(key->Get(),
                                           keyAlgorithm,
                                           *cfHash,
                                           *cfSignature,
                                           NULL);
        
        active = false;
        
        return ok ? CKR_OK : CKR_SIGNATURE_INVALID;
    }
    CATCH_EXCEPTION
}
