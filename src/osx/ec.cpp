#include "ec.h"

#include <Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include "aes.h"
#include "helper.h"

using namespace osx;

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
        
        auto params = publicTemplate->GetBytes(CKA_EC_PARAMS, true, "");
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
        privateKey->Assign(pPrivateKey);
        
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
        SecAsn1CoderRef coder;
        SecAsn1CoderCreate(&coder);
        
        SecAsn1Item publicData;
        if (SecAsn1Decode(coder,
                          params->pPublicData,
                          params->ulPublicDataLen,
                          kSecAsn1OctetStringTemplate,
                          &publicData)) {
            SecAsn1CoderRelease(coder);
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "Cannot decode public data");
        }
        CFDataRef keyData = CFDataCreate(NULL, publicData.Data, publicData.Length);
        CFRef<CFMutableDictionaryRef> keyAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFDictionarySetValue(&keyAttr, kSecAttrKeyType, kSecAttrKeyTypeEC);
        // SecItemDelete(<#CFDictionaryRef  _Nonnull query#>)

        {
            puts("KeyData");
            auto data = CFDataGetBytePtr(keyData);
            for (int i = 0; i < CFDataGetLength(keyData); i++) {
                fprintf(stdout, "%02X", data[i]);
            }
            puts("");
        }
        
        SecKeyRef publicKey = SecKeyCreateFromData(&keyAttr,
                                                   keyData,
                                                   NULL);
        CFRef<CFMutableDictionaryRef> parameters = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                          0,
                                                                          &kCFTypeDictionaryKeyCallBacks,
                                                                          &kCFTypeDictionaryValueCallBacks);
        CFRef<CFDataRef> derivedData = SecKeyCopyKeyExchangeResult(privateKey->Get(),
                                                                   kSecKeyAlgorithmECDHKeyExchangeStandard,
                                                                   publicKey,
                                                                   &parameters,
                                                                   NULL);
        
        SecAsn1CoderRelease(coder);
        if (derivedData.IsEmpty()) {
            THROW_EXCEPTION("Error on SecKeyCopyKeyExchangeResult");
        }
        
        puts("Derived");
        auto data = CFDataGetBytePtr(&derivedData);
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
        
        auto propPoint = Scoped<std::string>(new std::string(""));
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
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
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
        
        auto propPoint = Scoped<std::string>(new std::string(""));
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
