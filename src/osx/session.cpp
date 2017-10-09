#include "session.h"

#include "../core/crypto.h"

#include "crypto.h"
#include "aes.h"
#include "rsa.h"
#include "ec.h"

#include "certificate.h"
#include "data.h"
#include "x509_template.h"
#include "helper.h"
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>

using namespace osx;

/**
 Creates copy for SecKeyRef by getting the same SecKeyRef from Keychain
 If it cannot get SecKeyRef from chain it returns NULL
 
 @param key Key wich must be copied
 @return Copy of SecKeyRef. Returns NULL if cannot copy key
 */
SecKeyRef SecKeyCopyRef(SecKeyRef key) {
    LOGGER_FUNCTION_BEGIN;
    
    CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(key);
    CFDataRef klbl = (CFDataRef)CFDictionaryGetValue(*attrs, kSecAttrApplicationLabel);
    if (klbl == NULL) {
        return NULL;
    }
    CFStringRef kcls = (CFStringRef) CFDictionaryGetValue(*attrs, kSecAttrKeyClass);
    if (kcls == NULL) {
        return NULL;
    }
    
    // create query
    CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                        0,
                                                                        &kCFTypeDictionaryKeyCallBacks,
                                                                        &kCFTypeDictionaryValueCallBacks);
    CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassKey);
    CFDictionaryAddValue(*matchAttr, kSecAttrKeyClass, kcls);
    CFDictionaryAddValue(*matchAttr, kSecAttrApplicationLabel, klbl);
    CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
    
    SecKeyRef result = NULL;
    OSStatus status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&result);
    if (status) {
        return NULL;
    }
    return result;
}

/*
 Copies SecKeyRef to core::Objecte
 */
Scoped<core::Object> SecKeyCopyObject(SecKeyRef key) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        if (key == NULL) {
            THROW_EXCEPTION("Parameter 'key' is empty");
        }
        Scoped<core::Object> result;
        SecKeyRef copyKey = SecKeyCopyRef(key);
        if (copyKey == NULL){
            THROW_EXCEPTION("Cannot copy SekKeyRef");
        }
        CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(copyKey);
        CFStringRef keyType  = (CFStringRef)CFDictionaryGetValue(*attrs, kSecAttrKeyType);
        if (keyType == NULL) {
            THROW_EXCEPTION("Cannot get kSecAttrKeyType from SecKeyRef");
        }
        CFStringRef keyClass  = (CFStringRef)CFDictionaryGetValue(*attrs, kSecAttrKeyClass);
        if (keyClass == NULL) {
            THROW_EXCEPTION("Cannot get kSecAttrKeyClass from SecKeyRef");
        }
        
        if (CFStringCompare(keyType, kSecAttrKeyTypeRSA, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (CFStringCompare(keyClass, kSecAttrKeyClassPrivate, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                Scoped<RsaPrivateKey> rsaKey(new RsaPrivateKey);
                rsaKey->Assign(copyKey);
                result = rsaKey;
            } else {
                Scoped<RsaPublicKey> rsaKey(new RsaPublicKey);
                rsaKey->Assign(copyKey);
                result = rsaKey;
            }
        } else if (CFStringCompare(keyType, kSecAttrKeyTypeEC, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (CFStringCompare(keyClass, kSecAttrKeyClassPrivate, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                Scoped<EcPrivateKey> ecKey(new EcPrivateKey);
                ecKey->Assign(copyKey);
                result = ecKey;
            } else {
                Scoped<EcPublicKey> ecKey(new EcPublicKey);
                ecKey->Assign(copyKey);
                result = ecKey;
            }
        } else {
            THROW_EXCEPTION("Unsupported key type in use");
        }
        
        return result;
    }
    CATCH_EXCEPTION
}


Scoped<core::Object> osx::Session::CreateObject
(
 CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
 CK_ULONG                ulCount      /* attributes in template */
)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Template tmpl(pTemplate, ulCount);
        
        Scoped<core::Object> object;
        switch (tmpl.GetNumber(CKA_CLASS, true)) {
            case CKO_SECRET_KEY:
                switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
                    case CKK_AES:
                        object = Scoped<AesKey>(new AesKey());
                        break;
                    default:
                        THROW_PKCS11_TEMPLATE_INCOMPLETE();
                }
                break;
            case CKO_PUBLIC_KEY: {
                switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
                    case CKK_RSA:
                        object = Scoped<RsaPublicKey>(new RsaPublicKey);
                        break;
                    case CKK_EC:
                        object = Scoped<EcPublicKey>(new EcPublicKey);
                        break;
                    default:
                        THROW_PKCS11_TEMPLATE_INCOMPLETE();
                }
                break;
            }
            case CKO_CERTIFICATE: {
                switch (tmpl.GetNumber(CKA_CERTIFICATE_TYPE, true)) {
                    case CKC_X_509:
                        object = Scoped<X509Certificate>(new X509Certificate);
                        break;
                    default:
                        THROW_PKCS11_TEMPLATE_INCOMPLETE();
                }
                break;
            }
            case CKO_DATA: {
                object = Scoped<Data>(new Data);
                break;
            }
            default:
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
        }
        
        object->CreateValues(pTemplate, ulCount);
        
        return object;
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> osx::Session::CopyObject
(
 Scoped<core::Object> object,      /* the object for copying */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
 CK_ULONG             ulCount      /* attributes in template */
)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        Scoped<core::Object> copy;
        if (dynamic_cast<X509Certificate*>(object.get())) {
            copy = Scoped<X509Certificate>(new X509Certificate());
        }
        else if (dynamic_cast<Data*>(object.get())) {
            copy = Scoped<Data>(new Data());
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object is not copyable");
        }
        
        copy->CopyValues(object, pTemplate, ulCount);
        return copy;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Open
(
 CK_FLAGS              flags,         /* from CK_SESSION_INFO */
 CK_VOID_PTR           pApplication,  /* passed to callback */
 CK_NOTIFY             Notify,        /* callback function */
 CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Session::Open(flags,
                            pApplication,
                            Notify,
                            phSession);
        
        digest = Scoped<CryptoDigest>(new CryptoDigest());
        encrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_ENCRYPT));
        decrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_DECRYPT));
        sign = Scoped<core::CryptoSign>(new core::CryptoSign(CRYPTO_SIGN));
        verify = Scoped<core::CryptoSign>(new core::CryptoSign(CRYPTO_VERIFY));
        
        OSStatus status;
        
        // Get keychain certificates and linked keys
        {
            CFRef<SecKeychainRef> loginKeychain;
            const char* HOME = getenv("HOME");
            std::string loginKeyChainPath("");
            loginKeyChainPath += HOME;
            loginKeyChainPath += "/Library/Keychains/login.keychain";
            OSStatus status = SecKeychainOpen(loginKeyChainPath.c_str(), &loginKeychain);
            if (status) {
                THROW_OSX_EXCEPTION(status, "SecKeychainOpen");
            }
            
            CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                                0,
                                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                                &kCFTypeDictionaryValueCallBacks);
            CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassCertificate);
            CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitAll);
            CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
            
            // Add loging keychain to limit list
            CFRef<CFArrayRef> matchSearchList;
            if (!loginKeychain.IsEmpty()){
                SecKeychainRef keychainArray[] = {*loginKeychain};
                matchSearchList = CFArrayCreate(NULL, (const void**)keychainArray, 1, &kCFTypeArrayCallBacks);
                CFDictionaryAddValue(*matchAttr, kSecMatchSearchList, &matchSearchList);
            }
            
            CFRef<CFArrayRef> result;
            status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&result);
            if (!status) {
                CFIndex itemsCount = CFArrayGetCount(*result);
                
                CFIndex index = 0;
                while (index < itemsCount) {
                    SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(*result, index++);
                    
                    X509Certificate x509;
                    x509.Assign(cert, false);
                    
                    try {
                        
                        Scoped<core::PublicKey> publicKey = x509.GetPublicKey();
                        
                        Key* pKey = dynamic_cast<Key*>(publicKey.get());
                        if (pKey == NULL) {
                            THROW_EXCEPTION("Cannot convert PublicKey to Key");
                        }
                        
                        publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                        
                        if (x509.HasPrivateKey()) {
                            Scoped<core::PrivateKey> privateKey = x509.GetPrivateKey();
                            privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                            objects.add(privateKey);
                        }
                        objects.add(publicKey);
                        
                        Scoped<X509Certificate> x509Copy = x509.Copy();
                        x509Copy->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                        
                        objects.add(x509Copy);
                    }
                    catch (Scoped<core::Exception> e) {
                        LOGGER_ERROR("Cannot load certificate. %s", e->what());
                    }
                    catch(...) {
                        LOGGER_ERROR("Cannot load certificate. Uknown exception");
                    }
                }
            }
        }
        
        // Get all keys from keychain matching to label
        {
            CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                                0,
                                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                                &kCFTypeDictionaryValueCallBacks);
            CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassKey);
            CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitAll);
            CFDictionaryAddValue(*matchAttr, kSecAttrLabel, kSecAttrLabelModule);
            CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
            
            CFRef<CFArrayRef> result;
            status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&result);
            if (!status) {
                CFIndex arrayCount = CFArrayGetCount(*result);
                
                CFIndex index = 0;
                while (index < arrayCount) {
                    SecKeyRef secKey = (SecKeyRef)CFArrayGetValueAtIndex(*result, index++);
                    Scoped<core::Object> key = SecKeyCopyObject(secKey);
                    
                    // Don't add tokens which were added before
                    CK_LONG searchIndex = 0;
                    while (searchIndex < objects.count()) {
                        Scoped<core::Object> object = objects.items(searchIndex++);
                        if (object->ItemByType(CKA_CLASS)->ToNumber() == key->ItemByType(CKA_CLASS)->ToNumber() &&
                            object->ItemByType(CKA_KEY_TYPE)->ToNumber() == key->ItemByType(CKA_KEY_TYPE)->ToNumber()) {
                            Scoped<Buffer> keyId1 = object->ItemByType(CKA_ID)->ToBytes();
                            Scoped<Buffer> keyId2 = key->ItemByType(CKA_ID)->ToBytes();
                            if (keyId1->size() == keyId2->size() &&
                                !memcmp(keyId1->data(), keyId2->data(), keyId1->size())) {
                                break;
                            }
                        }
                    }
                    if (searchIndex < objects.count()) {
                        continue;
                    }
                    
                    key->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    
                    objects.add(key);
                }
            }
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Close()
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::GenerateRandom
(
 CK_BYTE_PTR       pPart,     /* data to be digested */
 CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    try {
        core::Session::GenerateRandom(
                                      pPart,
                                      ulPartLen
                                      );
        
        FILE *fp = fopen("/dev/random", "r");
        if (!fp) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Cannot get /dev/random");
        }
        
        for (int i=0; i<ulPartLen; i++) {
            pPart[i] = fgetc(fp);
        }
        
        fclose(fp);
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::GenerateKey
(
 CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
 CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
 CK_ULONG             ulCount,     /* # of attrs in template */
 CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
    try {
        core::Session::GenerateKey(
                                   pMechanism,
                                   pTemplate,
                                   ulCount,
                                   phKey
                                   );
        
        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulCount));
        
        Scoped<core::SecretKey> key;
        switch (pMechanism->mechanism) {
            case CKM_AES_KEY_GEN:
                key = AesKey::Generate(
                                       pMechanism,
                                       tmpl
                                       );
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        // add key to session's objects
        objects.add(key);
        
        // set handles for keys
        *phKey = key->handle;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::GenerateKeyPair
(
 CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
 CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
 CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
 CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
 CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
 CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
 CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
)
{
    try {
        core::Session::GenerateKeyPair(
                                       pMechanism,
                                       pPublicKeyTemplate,
                                       ulPublicKeyAttributeCount,
                                       pPrivateKeyTemplate,
                                       ulPrivateKeyAttributeCount,
                                       phPublicKey,
                                       phPrivateKey
                                       );
        
        Scoped<core::Template> publicTemplate(new core::Template(pPublicKeyTemplate, ulPublicKeyAttributeCount));
        Scoped<core::Template> privateTemplate(new core::Template(pPrivateKeyTemplate, ulPrivateKeyAttributeCount));
        
        Scoped<core::KeyPair> keyPair;
        switch (pMechanism->mechanism) {
            case CKM_RSA_PKCS_KEY_PAIR_GEN:
                keyPair = RsaKey::Generate(
                                           pMechanism,
                                           publicTemplate,
                                           privateTemplate
                                           );
                break;
            case CKM_ECDSA_KEY_PAIR_GEN:
                keyPair = EcKey::Generate(
                                          pMechanism,
                                          publicTemplate,
                                          privateTemplate
                                          );
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        // add key to session's objects
        objects.add(keyPair->publicKey);
        objects.add(keyPair->privateKey);
        
        // set handles for keys
        *phPublicKey = keyPair->publicKey->handle;
        *phPrivateKey = keyPair->privateKey->handle;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::DeriveKey
(
 CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
 CK_OBJECT_HANDLE     hBaseKey,          /* base key */
 CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
 CK_ULONG             ulAttributeCount,  /* template length */
 CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    try {
        core::Session::DeriveKey(pMechanism,
                                 hBaseKey,
                                 pTemplate,
                                 ulAttributeCount,
                                 phKey);
        
        Scoped<core::Object> baseKey = GetObject(hBaseKey);
        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulAttributeCount));
        
        Scoped<core::Object> derivedKey;
        switch (pMechanism->mechanism) {
            case CKM_ECDH1_DERIVE: {
                derivedKey = EcKey::DeriveKey(pMechanism,
                                              baseKey,
                                              tmpl);
                break;
            }
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        // add key to session's objects
        objects.add(baseKey);
        
        // set handle for key
        *phKey = derivedKey->handle;
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::EncryptInit
(
 CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
 CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
    try {
        core::Session::EncryptInit(
                                   pMechanism,
                                   hKey
                                   );
        
        if (encrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }
        
        switch (pMechanism->mechanism) {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
            case CKM_AES_ECB:
                encrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_ENCRYPT));
                break;
            case CKM_AES_GCM:
                encrypt = Scoped<CryptoAesGCMEncrypt>(new CryptoAesGCMEncrypt(CRYPTO_ENCRYPT));
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        return encrypt->Init(
                             pMechanism,
                             GetObject(hKey)
                             );
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::DecryptInit
(
 CK_MECHANISM_PTR  pMechanism,
 CK_OBJECT_HANDLE  hKey
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Session::DecryptInit(
                                   pMechanism,
                                   hKey
                                   );
        
        if (decrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }
        
        switch (pMechanism->mechanism) {
            case CKM_AES_CBC:
            case CKM_AES_CBC_PAD:
            case CKM_AES_ECB:
                decrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_DECRYPT));
                break;
            case CKM_AES_GCM:
                decrypt = Scoped<CryptoAesGCMEncrypt>(new CryptoAesGCMEncrypt(CRYPTO_DECRYPT));
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        return decrypt->Init(
                             pMechanism,
                             GetObject(hKey)
                             );
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::SignInit
(
 CK_MECHANISM_PTR  pMechanism,
 CK_OBJECT_HANDLE  hKey
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Session::SignInit(
                                pMechanism,
                                hKey
                                );
        
        if (decrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }
        
        switch (pMechanism->mechanism) {
            case CKM_SHA1_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA384_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
                sign = Scoped<RsaPKCS1Sign>(new RsaPKCS1Sign(CRYPTO_SIGN));
                break;
            case CKM_ECDSA_SHA1:
            case CKM_ECDSA_SHA256:
            case CKM_ECDSA_SHA384:
            case CKM_ECDSA_SHA512:
                sign = Scoped<EcDsaSign>(new EcDsaSign(CRYPTO_SIGN));
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        return sign->Init(
                          pMechanism,
                          GetObject(hKey));
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::VerifyInit
(
 CK_MECHANISM_PTR  pMechanism,
 CK_OBJECT_HANDLE  hKey
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Session::VerifyInit(
                                  pMechanism,
                                  hKey
                                  );
        
        if (decrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }
        
        switch (pMechanism->mechanism) {
            case CKM_SHA1_RSA_PKCS:
            case CKM_SHA256_RSA_PKCS:
            case CKM_SHA384_RSA_PKCS:
            case CKM_SHA512_RSA_PKCS:
                verify = Scoped<RsaPKCS1Sign>(new RsaPKCS1Sign(CRYPTO_VERIFY));
                break;
            case CKM_ECDSA_SHA1:
            case CKM_ECDSA_SHA256:
            case CKM_ECDSA_SHA384:
            case CKM_ECDSA_SHA512:
                verify = Scoped<EcDsaSign>(new EcDsaSign(CRYPTO_VERIFY));
                break;
            default:
                THROW_PKCS11_MECHANISM_INVALID();
        }
        
        return verify->Init(
                            pMechanism,
                            GetObject(hKey));
    }
    CATCH_EXCEPTION;
}
