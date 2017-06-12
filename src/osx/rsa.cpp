#include "rsa.h"

// #include <CommonCrypto/CommonCrypto.h>
#include <Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include <Security/x509defs.h>

using namespace osx;

typedef struct {
    SecAsn1Item modulus;
    SecAsn1Item publicExponent;
} ASN1_RSA_PUBLIC_KEY;

const SecAsn1Template kRsaPublicKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PUBLIC_KEY) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, modulus) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, publicExponent) },
    { 0 },
};

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

void osx::RsaPublicKey::Dispose()
{
    if (value) {
        CFRelease(value);
        value = NULL;
    }
}

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

void osx::RsaPublicKey::Assign(SecKeyRef key)
{
    try {
        if (key == NULL) {
            THROW_EXCEPTION("SecKeyRef is empty");
        }
        
        value = key;
        
        FillKeyStruct();
    }
    CATCH_EXCEPTION
}

void osx::RsaPublicKey::FillKeyStruct()
{
    try {
        CFDictionaryRef cfAttributes = SecKeyCopyAttributes(value);
        if (!cfAttributes) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        Scoped<void> attributes((void*)cfAttributes, CFRelease);
        
        CFDataRef cfLabel = (CFDataRef)CFDictionaryGetValue(cfAttributes, kSecAttrApplicationLabel);
        if (cfLabel) {
            ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
                                                                        (CK_BYTE_PTR)CFDataGetBytePtr(cfLabel),
                                                                        CFDataGetLength(cfLabel)
                                                                        );
        }
        
        // Get public key SEQUENCE
        CFDataRef cfKeyData = SecKeyCopyExternalRepresentation(value, NULL);
        if (!cfKeyData) {
            THROW_EXCEPTION("Erro on SecKeyCopyExternalRepresentation");
        }
        Scoped<void> keyData((void*)cfKeyData, CFRelease);
        
        // Init ASN1 coder
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        ASN1_RSA_PUBLIC_KEY asn1PublicKey;
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(cfKeyData),
                                        CFDataGetLength(cfKeyData),
                                        kRsaPublicKeyTemplate,
                                        &asn1PublicKey);
        if (status) {
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Error on SecAsn1Decode");
        }
        
        ItemByType(CKA_MODULUS_BITS)->To<core::AttributeNumber>()->Set(asn1PublicKey.modulus.Length * 8);
        
        ItemByType(CKA_MODULUS)->SetValue(asn1PublicKey.modulus.Data,
                                          asn1PublicKey.modulus.Length);
        
        ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(asn1PublicKey.publicExponent.Data,
                                          asn1PublicKey.publicExponent.Length);
        
//        SecAsn1CoderRelease(coder);
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPublicKey::GetValue(
                                  CK_ATTRIBUTE_PTR  attr
                                  )
{
    try {
        switch (attr->type) {
            case CKA_MODULUS:
            case CKA_MODULUS_BITS:
            case CKA_PUBLIC_EXPONENT: {
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillKeyStruct();
                }
                break;
            }
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}
