#include "rsa.h"

//#include <CommonCrypto/CommonCrypto.h>
#include <Security.h>

using namespace osx;
    
Scoped<core::KeyPair> osx::RsaKey::Generate(
    CK_MECHANISM_PTR       pMechanism,
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
    try {
        if (pMechanism == NULL) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }
        
        Scoped<RsaPrivateKey> privateKey(new RsaPrivateKey());
        privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());
        
        Scoped<RsaPublicKey> publicKey(new RsaPublicKey());
        publicKey->GenerateValues(publicTemplate->Get(), publicTemplate->Size());
        
        CFMutableDictionaryRef privateKeyAttr = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );
        CFMutableDictionaryRef publicKeyAttr = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );
        CFMutableDictionaryRef keyPairAttr = CFDictionaryCreateMutable(
            kCFAllocatorDefault, 0, &kCFTypeDictionaryKeyCallBacks,
            &kCFTypeDictionaryValueCallBacks
        );
        
        // CFDataRef publicTag = [publicTagString dataUsingEncoding:NSUTF8StringEncoding];
	    // CFDataRef privateTag = [privateTagString dataUsingEncoding:NSUTF8StringEncoding];
        
        SecKeyRef pPrivateKey = NULL;
        SecKeyRef pPublicKey = NULL;
        
        CFDictionarySetValue(keyPairAttr, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        int32_t modulusBits = publicTemplate->GetNumber(CKA_MODULUS_BITS, true);
        CFNumberRef cfModulusBits = CFNumberCreate(kCFAllocatorDefault,
                                         kCFNumberSInt32Type, &modulusBits);
        CFDictionarySetValue(keyPairAttr, kSecAttrKeySizeInBits, cfModulusBits);
        
        CFStringRef cfPrivateLabel = CFStringCreateWithCString(NULL, "WebCrypto Local", kCFStringEncodingUTF8);
        CFDictionarySetValue(privateKeyAttr, kSecAttrLabel, cfPrivateLabel);
        CFDictionarySetValue(privateKeyAttr, kSecUseKeychain, NULL);
        
        CFDictionarySetValue(keyPairAttr, kSecPrivateKeyAttrs, privateKeyAttr);
        
        CFStringRef cfPublicLabel = CFStringCreateWithCString(NULL, "WebCrypto Local", kCFStringEncodingUTF8);
        CFDictionarySetValue(publicKeyAttr, kSecAttrLabel, cfPublicLabel);
        CFDictionarySetValue(publicKeyAttr, kSecUseKeychain, NULL);
        CFDictionarySetValue(keyPairAttr, kSecPublicKeyAttrs, publicKeyAttr);

        
        // Public exponent
        auto publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
        char PUBLIC_EXPONENT_65537[3] = { 1,0,1 };
        if (!(publicExponent->size() == 3 && !memcmp(publicExponent->data(), PUBLIC_EXPONENT_65537, 3))) {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
        }
        
        OSStatus err = SecKeyGeneratePair(keyPairAttr, &pPublicKey, &pPrivateKey);
        
        if(publicKey) CFRelease(pPublicKey);
        if(privateKey) CFRelease(pPrivateKey);
        
        // privateKey->Assign(key);
        // publicKey->Assign(key);
        
        return Scoped<core::KeyPair>(new core::KeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION
}

// RsaPrivateKey
        
CK_RV osx::RsaPrivateKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
CK_RV osx::RsaPrivateKey::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
void osx::RsaPrivateKey::OnKeyAssigned()
{
    try {

    }
    CATCH_EXCEPTION
}
        
void osx::RsaPrivateKey::FillPublicKeyStruct()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

void osx::RsaPrivateKey::FillPrivateKeyStruct()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
CK_RV osx::RsaPrivateKey::GetValue(
    CK_ATTRIBUTE_PTR attr
)
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

// RsaPublicKey

 CK_RV osx::RsaPublicKey::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
CK_RV osx::RsaPublicKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
CK_RV osx::RsaPublicKey::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

void osx::RsaPublicKey::OnKeyAssigned()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

void osx::RsaPublicKey::FillKeyStruct()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
        
CK_RV osx::RsaPublicKey::GetValue(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
