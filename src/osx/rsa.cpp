#include "rsa.h"

#include <Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include "helper.h"

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

typedef struct {
    SecAsn1Item version;
    SecAsn1Item modulus;
    SecAsn1Item publicExponent;
    SecAsn1Item privateExponent;
    SecAsn1Item prime1;
    SecAsn1Item prime2;
    SecAsn1Item exponent1;
    SecAsn1Item exponent2;
    SecAsn1Item coefficient;
} ASN1_RSA_PRIVATE_KEY;

const SecAsn1Template kRsaPrivateKeyTemplate[] = {
    { SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PRIVATE_KEY) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, version) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, modulus) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, publicExponent) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, privateExponent) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime1) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime2) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent1) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent2) },
    { SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, coefficient) },
    { 0 },
};


Scoped<core::KeyPair> osx::RsaKey::Generate
(
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
        
        CFMutableDictionaryRef privateKeyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFMutableDictionaryRef publicKeyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                         0,
                                                                         &kCFTypeDictionaryKeyCallBacks,
                                                                         &kCFTypeDictionaryValueCallBacks);
        CFMutableDictionaryRef keyPairAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                       0,
                                                                       &kCFTypeDictionaryKeyCallBacks,
                                                                       &kCFTypeDictionaryValueCallBacks);
        
        SecKeyRef pPrivateKey = NULL;
        SecKeyRef pPublicKey = NULL;
        
        CFDictionarySetValue(keyPairAttr, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        int32_t modulusBits = (int32_t)publicTemplate->GetNumber(CKA_MODULUS_BITS, true);
        CFRef<CFNumberRef> cfModulusBits = CFNumberCreate(kCFAllocatorDefault,
                                                          kCFNumberSInt32Type,
                                                          &modulusBits);
        CFDictionarySetValue(keyPairAttr, kSecAttrKeySizeInBits, &cfModulusBits);
        
        CFDictionarySetValue(privateKeyAttr, kSecAttrLabel, kSecAttrLabelModule);
        CFDictionarySetValue(keyPairAttr, kSecPrivateKeyAttrs, privateKeyAttr);
        
        CFDictionarySetValue(publicKeyAttr, kSecAttrLabel, kSecAttrLabelModule);
        CFDictionarySetValue(keyPairAttr, kSecPublicKeyAttrs, publicKeyAttr);
        
        
        // Public exponent
        Scoped<Buffer> publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
        char PUBLIC_EXPONENT_65537[3] = { 1,0,1 };
        if (!(publicExponent->size() == 3 && !memcmp(publicExponent->data(), PUBLIC_EXPONENT_65537, 3))) {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
        }
        
        OSStatus status = SecKeyGeneratePair(keyPairAttr, &pPublicKey, &pPrivateKey);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecKeyGeneratePair");
        }
        
        
        publicKey->Assign(pPublicKey);
        publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
        privateKey->Assign(pPrivateKey);
        privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
        
        return Scoped<core::KeyPair>(new core::KeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION
}

// RsaPrivateKey

void osx::RsaPrivateKey::Assign(SecKeyRef key)
{
    value = key;
    
    CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&value);
    if (!&cfAttributes) {
        THROW_EXCEPTION("Error on SecKeyCopyAttributes");
    }
    
    CFDataRef cfLabel = (CFDataRef)CFDictionaryGetValue(&cfAttributes, kSecAttrApplicationLabel);
    if (cfLabel) {
        ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
                                                                    (CK_BYTE_PTR)CFDataGetBytePtr(cfLabel),
                                                                    CFDataGetLength(cfLabel)
                                                                    );
    }
    CFDataRef cfAppLabel = (CFDataRef)CFDictionaryGetValue(&cfAttributes, kSecAttrApplicationLabel);
    if (cfAppLabel) {
        ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)CFDataGetBytePtr(cfAppLabel),
                                                            CFDataGetLength(cfAppLabel));
    }
    CFBooleanRef cfSign = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanSign);
    if (CFBooleanGetValue(cfSign)) {
        ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfDecrypt = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanDecrypt);
    if (CFBooleanGetValue(cfDecrypt)) {
        ItemByType(CKA_DECRYPT)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfUnwrap = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanUnwrap);
    if (CFBooleanGetValue(cfUnwrap)) {
        ItemByType(CKA_UNWRAP)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfExtractable = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrIsExtractable);
    if (CFBooleanGetValue(cfExtractable)) {
        ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->Set(true);
    }
}

CK_RV osx::RsaPrivateKey::CopyValues
(
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

void osx::RsaPrivateKey::FillPublicKeyStruct()
{
    try {
        // CFShow(&value);
        CFRef<SecKeyRef> publicKey = SecKeyCopyPublicKeyEx(&value);
        
        if (publicKey.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyPublicKeyEx");
        }
        
        // Get public key SEQUENCE
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&publicKey, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }
        
        // Init ASN1 coder
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        ASN1_RSA_PUBLIC_KEY asn1PublicKey;
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(&cfKeyData),
                                        CFDataGetLength(&cfKeyData),
                                        kRsaPublicKeyTemplate,
                                        &asn1PublicKey);
        if (status) {
            SecAsn1CoderRelease(coder);
            THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
        }
        
        ItemByType(CKA_MODULUS)->SetValue(asn1PublicKey.modulus.Data,
                                          asn1PublicKey.modulus.Length);
        
        ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(asn1PublicKey.publicExponent.Data,
                                                  asn1PublicKey.publicExponent.Length);
        
        SecAsn1CoderRelease(coder);
    }
    CATCH_EXCEPTION
}

void osx::RsaPrivateKey::FillPrivateKeyStruct()
{
    try {
        // Get public key SEQUENCE
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&value, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }
        
        // Init ASN1 coder
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        ASN1_RSA_PRIVATE_KEY asn1PrivateKey;
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(&cfKeyData),
                                        CFDataGetLength(&cfKeyData),
                                        kRsaPrivateKeyTemplate,
                                        &asn1PrivateKey);
        if (status) {
            SecAsn1CoderRelease(coder);
            THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
        }
        
        ItemByType(CKA_PRIVATE_EXPONENT)->SetValue(asn1PrivateKey.privateExponent.Data,
                                                   asn1PrivateKey.privateExponent.Length);
        
        ItemByType(CKA_PRIME_1)->SetValue(asn1PrivateKey.prime1.Data,
                                          asn1PrivateKey.prime1.Length);
        
        ItemByType(CKA_PRIME_2)->SetValue(asn1PrivateKey.prime2.Data,
                                          asn1PrivateKey.prime2.Length);
        
        ItemByType(CKA_EXPONENT_1)->SetValue(asn1PrivateKey.exponent1.Data,
                                             asn1PrivateKey.exponent1.Length);
        
        ItemByType(CKA_EXPONENT_2)->SetValue(asn1PrivateKey.exponent2.Data,
                                             asn1PrivateKey.exponent2.Length);
        
        ItemByType(CKA_COEFFICIENT)->SetValue(asn1PrivateKey.coefficient.Data,
                                              asn1PrivateKey.coefficient.Length);
        
        SecAsn1CoderRelease(coder);
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPrivateKey::GetValue
(
 CK_ATTRIBUTE_PTR attr
 )
{
    try {
        switch (attr->type) {
            case CKA_MODULUS:
            case CKA_PUBLIC_EXPONENT:
            {
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillPublicKeyStruct();
                }
                break;
            }
            case CKA_PRIME_1:
            case CKA_PRIME_2:
            case CKA_EXPONENT_1:
            case CKA_EXPONENT_2:
            case CKA_PRIVATE_EXPONENT:
            {
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillPrivateKeyStruct();
                }
                break;
            }
            default:
                return core::RsaPrivateKey::GetValue(attr);
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

// RsaPublicKey

CK_RV osx::RsaPublicKey::CreateValues
(
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
 CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::RsaPublicKey::CreateValues(pTemplate, ulCount);
        
        core::Template tmpl(pTemplate, ulCount);
        
        ASN1_RSA_PUBLIC_KEY asn1Key;
        // Modulus
        Scoped<Buffer> modulus = tmpl.GetBytes(CKA_MODULUS, true);
        asn1Key.modulus.Data = modulus->data();
        asn1Key.modulus.Length = modulus->size();
        // Public exponent
        Scoped<Buffer> publicExponent = tmpl.GetBytes(CKA_PUBLIC_EXPONENT, true);
        asn1Key.publicExponent.Data = publicExponent->data();
        asn1Key.publicExponent.Length = publicExponent->size();
        
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        SecAsn1Item derKey;
        if (SecAsn1EncodeItem(coder, &asn1Key, kRsaPublicKeyTemplate, &derKey)) {
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Error onSecAsn1EncodeItem");
        }
        CFMutableDictionaryRef keyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                   0,
                                                                   &kCFTypeDictionaryKeyCallBacks,
                                                                   &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(keyAttr, kSecAttrKeyType, kSecAttrKeyTypeRSA);
        CFDictionaryAddValue(keyAttr, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFRef<CFDataRef> derKeyData = CFDataCreate(NULL, derKey.Data, derKey.Length);
        CFErrorRef error = NULL;
        SecKeyRef key = SecKeyCreateFromData(keyAttr, &derKeyData, &error);
        if (error) {
            CFRef<CFStringRef> errorText = CFErrorCopyDescription(error);
            THROW_EXCEPTION(CFStringGetCStringPtr(&errorText, kCFStringEncodingUTF8));
        }
        SecAsn1CoderRelease(coder);

        Assign(key);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPublicKey::CopyValues
(
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
            THROW_EXCEPTION("key is NULL");
        }
        value = key;
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&value);
        if (cfAttributes.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        CFDataRef cfAppLabel = (CFDataRef)CFDictionaryGetValue(&cfAttributes, kSecAttrApplicationLabel);
        if (cfAppLabel) {
            ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)CFDataGetBytePtr(cfAppLabel),
                                                                CFDataGetLength(cfAppLabel));
        }
        CFBooleanRef cfVerify = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanVerify);
        if (CFBooleanGetValue(cfVerify)) {
            ItemByType(CKA_VERIFY)->To<core::AttributeBool>()->Set(true);
        }
        CFBooleanRef cfEncrypt = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanEncrypt);
        if (CFBooleanGetValue(cfEncrypt)) {
            ItemByType(CKA_ENCRYPT)->To<core::AttributeBool>()->Set(true);
        }
        CFBooleanRef cfWrap = (CFBooleanRef)CFDictionaryGetValue(&cfAttributes, kSecAttrCanWrap);
        if (CFBooleanGetValue(cfWrap)) {
            ItemByType(CKA_WRAP)->To<core::AttributeBool>()->Set(true);
        }
        
        FillKeyStruct();
    }
    CATCH_EXCEPTION
}

void osx::RsaPublicKey::FillKeyStruct()
{
    try {
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&value);
        if (!&cfAttributes) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        
        CFDataRef cfLabel = (CFDataRef)CFDictionaryGetValue(&cfAttributes, kSecAttrApplicationLabel);
        if (cfLabel) {
            ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
                                                                        (CK_BYTE_PTR)CFDataGetBytePtr(cfLabel),
                                                                        CFDataGetLength(cfLabel)
                                                                        );
        }
        
        // Get public key SEQUENCE
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&value, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }
        
        // Init ASN1 coder
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        ASN1_RSA_PUBLIC_KEY asn1PublicKey;
        OSStatus status = SecAsn1Decode(coder,
                                        CFDataGetBytePtr(&cfKeyData),
                                        CFDataGetLength(&cfKeyData),
                                        kRsaPublicKeyTemplate,
                                        &asn1PublicKey);
        if (status) {
            SecAsn1CoderRelease(coder);
            THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
        }
        
        ItemByType(CKA_MODULUS_BITS)->To<core::AttributeNumber>()->Set(asn1PublicKey.modulus.Length * 8);
        
        ItemByType(CKA_MODULUS)->SetValue(asn1PublicKey.modulus.Data,
                                          asn1PublicKey.modulus.Length);
        
        ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(asn1PublicKey.publicExponent.Data,
                                                  asn1PublicKey.publicExponent.Length);
        
        SecAsn1CoderRelease(coder);
    }
    CATCH_EXCEPTION
}

CK_RV osx::RsaPublicKey::GetValue
(
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
