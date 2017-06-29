#include "ec.h"

#include <Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include "aes.h"
#include "helper.h"

using namespace osx;

typedef struct {
    SecAsn1Item     algorithm;
    SecAsn1Item     namedCurve;
} ASN1_EC_ALGORITHM_IDENTIFIER;

const SecAsn1Template kEcAlgorithmIdTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_ALGORITHM_IDENTIFIER)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, algorithm)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, namedCurve)},
    {0}
};

typedef struct {
    ASN1_EC_ALGORITHM_IDENTIFIER    algorithm;
    SecAsn1Item                     publicKey;
} ASN1_EC_PUBLIC_KEY;

const SecAsn1Template kEcPublicKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_PUBLIC_KEY)},
    {SEC_ASN1_INLINE, offsetof(ASN1_EC_PUBLIC_KEY, algorithm), kEcAlgorithmIdTemplate},
    {SEC_ASN1_BIT_STRING , offsetof(ASN1_EC_PUBLIC_KEY, publicKey)},
    {0}
};

CFDataRef GetKeyDataFromOctetString(CFDataRef octetString)
{
    SecAsn1CoderRef coder;
    SecAsn1CoderCreate(&coder);
    
    SecAsn1Item keyData;
    const UInt8* data = CFDataGetBytePtr(octetString);
    CFIndex dataLen = CFDataGetLength(octetString);
    OSStatus status = SecAsn1Decode(coder, data, dataLen, kSecAsn1OctetStringTemplate, &keyData);
    if (status) {
        SecAsn1CoderRelease(coder);
        return NULL;
    }
    
    CFDataRef res = CFDataCreate(kCFAllocatorDefault, keyData.Data, keyData.Length);
    
    SecAsn1CoderRelease(coder);
    
    return res;
}

CFDataRef CopyKeyDataToOctetString(UInt8* data, CFIndex dataLen)
{
    SecAsn1CoderRef coder;
    SecAsn1CoderCreate(&coder);
    
    SecAsn1Item octetString;
    octetString.Data = data;
    octetString.Length = dataLen;
    SecAsn1Item keyData;
    OSStatus status = SecAsn1EncodeItem(coder, &octetString, kSecAsn1OctetStringTemplate, &keyData);
    if (status) {
        SecAsn1CoderRelease(coder);
        return NULL;
    }
    
    CFDataRef res = CFDataCreate(kCFAllocatorDefault, keyData.Data, keyData.Length);
    
    SecAsn1CoderRelease(coder);
    
    return res;
}

CK_ULONG GetKeySize(UInt8* data, CFIndex dataLen) {
    if (data && dataLen && data[0] == 4) {
        switch ((dataLen - 1) >> 1) {
            case 32:
                return 256;
            case 48:
                return 384;
            case 66:
                return 521;
        }
    }
    return 0;
}

CFDataRef SetKeyDataToPublicKey(UInt8* data, CFIndex dataLen)
{
    SecAsn1CoderRef coder;
    SecAsn1CoderCreate(&coder);
    
    ASN1_EC_PUBLIC_KEY publicKey;
    publicKey.algorithm.algorithm.Data = (unsigned char*)"\x2A\x86\x48\xCE\x3D\x02\x01"; // ecPublicKey(ANSI X9.62 public key type)
    publicKey.algorithm.algorithm.Length = 7;
    
    CK_ULONG keySizeInBits = GetKeySize(data, dataLen);
    if (!keySizeInBits) {
        return NULL;
    }
    switch (keySizeInBits) {
        case 256:
            publicKey.algorithm.namedCurve.Data = (unsigned char*)"\x2A\x86\x48\xCE\x3D\x03\x01\x07";
            publicKey.algorithm.namedCurve.Length = 8;
            break;
        case 384:
            publicKey.algorithm.namedCurve.Data = (unsigned char*)"\x2B\x81\x04\x00\x22";
            publicKey.algorithm.namedCurve.Length = 5;
            break;
        case 521:
            publicKey.algorithm.namedCurve.Data = (unsigned char*)"\x2B\x81\x04\x00\x23";
            publicKey.algorithm.namedCurve.Length = 5;
            break;
        default:
            return NULL;
    }
    
    publicKey.publicKey.Data = data;
    publicKey.publicKey.Length = dataLen << 3;
    
    SecAsn1Item keyData;
    OSStatus status = SecAsn1EncodeItem(coder, &publicKey, kEcPublicKeyTemplate, &keyData);
    if (status) {
        SecAsn1CoderRelease(coder);
        return NULL;
    }
    
    CFDataRef res = CFDataCreate(kCFAllocatorDefault, keyData.Data, keyData.Length);
    
    SecAsn1CoderRelease(coder);
    
    return res;
}


Scoped<core::KeyPair> osx::EcKey::Generate
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
        if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }
        
        Scoped<EcPrivateKey> privateKey(new EcPrivateKey());
        privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());
        
        Scoped<EcPublicKey> publicKey(new EcPublicKey());
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
        
        Scoped<Buffer> params = publicTemplate->GetBytes(CKA_EC_PARAMS, true, "");
        unsigned int keySizeInBits = 0;
        
#define POINT_COMPARE(curve) memcmp(core::EC_##curve##_BLOB, params->data(), sizeof(core::EC_##curve##_BLOB)-1 ) == 0
        
        if (POINT_COMPARE(P256)) {
            keySizeInBits = 256;
        }
        else if (POINT_COMPARE(P384)) {
            keySizeInBits = 384;
        }
        else if (POINT_COMPARE(P521)) {
            keySizeInBits = 521;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Wrong POINT for EC key");
        }
        
#undef POINT_COMPARE
        
        CFDictionarySetValue(keyPairAttr, kSecAttrKeyType, kSecAttrKeyTypeEC);
        CFRef<CFNumberRef> cfKeySizeInBits = CFNumberCreate(NULL,
                                                            kCFNumberSInt32Type,
                                                            &keySizeInBits);
        CFDictionarySetValue(keyPairAttr, kSecAttrKeySizeInBits, &cfKeySizeInBits);
        
        CFRef<CFStringRef> cfPrivateLabel = CFStringCreateWithCString(NULL, "WebCrypto Local", kCFStringEncodingUTF8);
        CFDictionarySetValue(privateKeyAttr, kSecAttrLabel, &cfPrivateLabel);
        
        CFDictionarySetValue(keyPairAttr, kSecPrivateKeyAttrs, privateKeyAttr);
        
        CFRef<CFStringRef> cfPublicLabel = CFStringCreateWithCString(NULL, "WebCrypto Local", kCFStringEncodingUTF8);
        CFDictionarySetValue(publicKeyAttr, kSecAttrLabel, &cfPublicLabel);
        CFDictionarySetValue(keyPairAttr, kSecPublicKeyAttrs, publicKeyAttr);
        
        OSStatus status = SecKeyGeneratePair(keyPairAttr, &pPublicKey, &pPrivateKey);
        if (status) {
            THROW_EXCEPTION("Error on SecKeyGeneratePair");
        }
        
        
        publicKey->Assign(pPublicKey);
        CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(pPublicKey);
        publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
        privateKey->Assign(pPrivateKey);
        privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
        
        return Scoped<core::KeyPair>(new core::KeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> EcKey::DeriveKey
(
 CK_MECHANISM_PTR        pMechanism,
 Scoped<core::Object>    baseKey,
 Scoped<core::Template>  tmpl
 )
{
    try {
        EcPrivateKey* ecPrivateKey = dynamic_cast<EcPrivateKey*>(baseKey.get());
        if (!ecPrivateKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "baseKey is not EC key");
        }
        
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_ECDH1_DERIVE) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism->mechanism is not CKM_ECDH1_DERIVE");
        }
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }
        CK_ECDH1_DERIVE_PARAMS_PTR params = static_cast<CK_ECDH1_DERIVE_PARAMS_PTR>(pMechanism->pParameter);
        if (!params) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is not CK_ECDH1_DERIVE_PARAMS");
        }
        
        Key* privateKey = dynamic_cast<Key*>(baseKey.get());
        if (!privateKey) {
            THROW_EXCEPTION("Cannot get SecKeyRef from Object");
        }
        
        // Create public key from public data
        CFRef<CFDataRef> publicData = CFDataCreate(NULL, params->pPublicData, params->ulPublicDataLen);
        CFRef<CFDataRef> keyData = GetKeyDataFromOctetString(&publicData);
        if (keyData.IsEmpty()) {
            THROW_EXCEPTION("Error on GetKeyDataFromOctetString");
        }
        const UInt8* keyDataBytes = CFDataGetBytePtr(&keyData);
        CFIndex keyDataLength = CFDataGetLength(&keyData);
        CFRef<CFDataRef> spki = SetKeyDataToPublicKey((UInt8*)keyDataBytes, keyDataLength);
        if (spki.IsEmpty()) {
            THROW_EXCEPTION("Error on SetKeyDataToPublicKey");
        }
        
        CFRef<CFMutableDictionaryRef> keyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&keyAttr, kSecAttrKeyType, kSecAttrKeyTypeEC);
        CFDictionaryAddValue(&keyAttr, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        
        CFErrorRef error = NULL;
        SecKeyRef publicKey = SecKeyCreateFromData(&keyAttr,
                                                   &spki,
                                                   &error);
        CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(publicKey);
        CFRef<CFDataRef> blob = SecKeyCopyExternalRepresentation(publicKey, NULL);
        if (error) {
            THROW_EXCEPTION("Error on SecKeyCreateFromData");
        }
        CFRef<CFMutableDictionaryRef> parameters = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFRef<CFDataRef> derivedData = SecKeyCopyKeyExchangeResult(privateKey->Get(),
                                                                   kSecKeyAlgorithmECDHKeyExchangeStandard,
                                                                   publicKey,
                                                                   &parameters,
                                                                   NULL);
        
        if (derivedData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyKeyExchangeResult");
        }
        
        puts("Derived");
        const UInt8* data = CFDataGetBytePtr(&derivedData);
        for (int i = 0; i < CFDataGetLength(&derivedData); i++) {
            fprintf(stdout, "%02X", data[i]);
        }
        puts("");
        
        THROW_EXCEPTION("Not finished");
    }
    CATCH_EXCEPTION
}

// EcPrivateKey

void osx::EcPrivateKey::Assign(SecKeyRef key)
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

CK_RV osx::EcPrivateKey::CopyValues
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

CK_RV osx::EcPrivateKey::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

void osx::EcPrivateKey::FillPublicKeyStruct()
{
    try {
        CFRef<SecKeyRef> publicKey = SecKeyCopyPublicKey(&value);
        
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&publicKey);
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
        
        CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(&cfAttributes, kSecAttrKeySizeInBits);
        if (!cfKeySizeInBits) {
            THROW_EXCEPTION("Cannot get size of key");
        }
        CK_ULONG keySizeInBits = 0;
        CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt64Type, &keySizeInBits);
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&value, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }
        
        Scoped<std::string> propPoint(new std::string(""));
        switch (keySizeInBits) {
            case 256:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, sizeof(core::EC_P256_BLOB) - 1);
                break;
            case 384:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, sizeof(core::EC_P384_BLOB) - 1);
                break;
            case 521:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, sizeof(core::EC_P521_BLOB) - 1);
                break;
            default:
                THROW_EXCEPTION("Unsuported size of key");
        }
    }
    CATCH_EXCEPTION
}

void osx::EcPrivateKey::FillPrivateKeyStruct()
{
    try {
        // Get public key SEQUENCE
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&value, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }
        
        // Get attributes of key
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&value);
        if (!&cfAttributes) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        
        // Get key size
        CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(&cfAttributes, kSecAttrKeySizeInBits);
        if (!cfKeySizeInBits) {
            THROW_EXCEPTION("Cannot get size of key");
        }
        CK_ULONG keySizeInBits = 0;
        CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt64Type, &keySizeInBits);
        keySizeInBits = (keySizeInBits+7) >> 3;
        
        // Get private part of the key
        ItemByType(CKA_VALUE)->SetValue((CK_VOID_PTR)(CFDataGetBytePtr(&cfKeyData) + (keySizeInBits * 2)),
                                        keySizeInBits);
    }
    CATCH_EXCEPTION
}

CK_RV osx::EcPrivateKey::GetValue
(
 CK_ATTRIBUTE_PTR attr
 )
{
    try {
        switch (attr->type) {
            case CKA_EC_PARAMS:
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillPublicKeyStruct();
                }
                break;
            case CKA_VALUE:
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillPrivateKeyStruct();
                }
                break;
            default:
                return core::EcPrivateKey::GetValue(attr);
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

// RsaPublicKey

CK_RV osx::EcPublicKey::CreateValues
(
 CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
 CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::EcPublicKey::CreateValues(pTemplate, ulCount);
        
        core::Template tmpl(pTemplate, ulCount);
        
        // POINT
        Scoped<Buffer> point = tmpl.GetBytes(CKA_EC_POINT, true);
        // PARAMS
        Scoped<Buffer> params = tmpl.GetBytes(CKA_EC_PARAMS, true);
        
        
        CFRef<CFDataRef> publicData = CFDataCreate(NULL, point->data(), point->size());
        CFRef<CFDataRef> keyData = GetKeyDataFromOctetString(&publicData);
        if (keyData.IsEmpty()) {
            THROW_EXCEPTION("Error on GetKeyDataFromOctetString");
        }
        const UInt8* keyDataBytes = CFDataGetBytePtr(&keyData);
        CFIndex keyDataLength = CFDataGetLength(&keyData);
        CFRef<CFDataRef> spki = SetKeyDataToPublicKey((UInt8*)keyDataBytes, keyDataLength);
        if (spki.IsEmpty()) {
            THROW_EXCEPTION("Error on SetKeyDataToPublicKey");
        }
        
        CFRef<CFMutableDictionaryRef> keyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&keyAttr, kSecAttrKeyType, kSecAttrKeyTypeEC);
        CFDictionaryAddValue(&keyAttr, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        
        // Set key usage
        if (tmpl.GetBool(CKA_VERIFY, false)) {
            CFDictionaryAddValue(&keyAttr, kSecAttrCanVerify, kCFBooleanTrue);
        }
        
        CFErrorRef error = NULL;
        SecKeyRef publicKey = SecKeyCreateFromData(&keyAttr,
                                                   &spki,
                                                   &error);
        if (error) {
            CFRef<CFStringRef> errorText = CFErrorCopyDescription(error);
            const char* text = CFStringGetCStringPtr(&errorText, kCFStringEncodingUTF8);
            THROW_EXCEPTION(text ? text : "Error on SecKeyCreateFromData");
        }
        
        Assign(publicKey);
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::EcPublicKey::CopyValues
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

CK_RV osx::EcPublicKey::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

void osx::EcPublicKey::Assign(SecKeyRef key)
{
    try {
        if (key == NULL) {
            THROW_EXCEPTION("SecKeyRef is empty");
        }
        
        value = key;
        
        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(&value);
        if (!&cfAttributes) {
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
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

void osx::EcPublicKey::FillKeyStruct()
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
        
        // Get key size
        CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(&cfAttributes, kSecAttrKeySizeInBits);
        if (!cfKeySizeInBits) {
            THROW_EXCEPTION("Cannot get size of key");
        }
        CK_ULONG keySizeInBits = 0;
        CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt64Type, &keySizeInBits);
        
        CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(&value, NULL);
        if (cfKeyData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
        }

        Scoped<std::string> propPoint(new std::string(""));
        switch (keySizeInBits) {
            case 256:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, sizeof(core::EC_P256_BLOB) - 1);
                *propPoint += std::string("\x04\x41");
                break;
            case 384:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, sizeof(core::EC_P384_BLOB) - 1);
                *propPoint += std::string("\x04\x61");
                break;
            case 521:
                ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, sizeof(core::EC_P521_BLOB) - 1);
                *propPoint += std::string("\x04\x81\x85");
                break;
            default:
                THROW_EXCEPTION("Unsuported size of key");
        }
        *propPoint += std::string((char*)CFDataGetBytePtr(&cfKeyData), CFDataGetLength(&cfKeyData));
        ItemByType(CKA_EC_POINT)->SetValue((CK_BYTE_PTR)propPoint->c_str(), propPoint->length() );
    }
    CATCH_EXCEPTION
}

CK_RV osx::EcPublicKey::GetValue
(
 CK_ATTRIBUTE_PTR  attr
 )
{
    try {
        switch (attr->type) {
            case CKA_EC_PARAMS:
            case CKA_EC_POINT:
                if (ItemByType(attr->type)->IsEmpty()) {
                    FillKeyStruct();
                }
                break;
            default:
                return core::EcPublicKey::GetValue(attr);
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}
