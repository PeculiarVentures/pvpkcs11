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

SecKeyRef SecKeyCreateCopy(SecKeyRef key) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        CFRef<CFMutableDictionaryRef> query = CFDictionaryCreateMutable();
        CFDictionarySetValue(*query, kSecClass, kSecClassKey);
        CFDictionarySetValue(*query, kSecValueRef, key);
        CFDictionarySetValue(*query, kSecReturnRef, kCFBooleanTrue);
        CFDictionarySetValue(*query, kSecMatchLimit, kSecMatchLimitOne);
        
        CFRef<SecKeyRef> res;
        OSStatus status = SecItemCopyMatching(*query, (CFTypeRef*)&res);
        if (status) {
            return res.Retain();
        }
        return NULL;
    }
    CATCH_EXCEPTION
}

/*
 Copies SecKeyRef to core::Objecte
 */
Scoped<core::Object> SecKeyCopyObject(CFDictionaryRef attrs) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        if (!attrs) {
            THROW_PARAM_REQUIRED_EXCEPTION("attrs");
        }
        
        SecKeyRef key = (SecKeyRef) CFDictionaryGetValue(attrs, kSecValueRef);
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION("kSecValueRef");
        }
        CFStringRef keyClass = (CFStringRef) CFDictionaryGetValue(attrs, kSecAttrKeyClass);
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION("kSecAttrKeyClass");
        }
        CFStringRef keyType = (CFStringRef) CFDictionaryGetValue(attrs, kSecAttrKeyType);
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION("kSecAttrKeyType");
        }
        
        Scoped<core::Object> result;
        CFRef<SecKeyRef> copyKey = SecKeyCreateCopy(key);
        if (copyKey.IsEmpty()) {
            THROW_EXCEPTION("Cannot copy key SecKeyCreateCopy");
        }
        
        if (CFStringCompare(keyType, kSecAttrKeyTypeRSA, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (CFStringCompare(keyClass, kSecAttrKeyClassPrivate, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                Scoped<RsaPrivateKey> rsaKey(new RsaPrivateKey);
                rsaKey->Assign(*copyKey);
                result = rsaKey;
            } else {
                Scoped<RsaPublicKey> rsaKey(new RsaPublicKey);
                rsaKey->Assign(*copyKey);
                result = rsaKey;
            }
        } else if (CFStringCompare(keyType, kSecAttrKeyTypeEC, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
            if (CFStringCompare(keyClass, kSecAttrKeyClassPrivate, kCFCompareCaseInsensitive) == kCFCompareEqualTo) {
                Scoped<EcPrivateKey> ecKey(new EcPrivateKey);
                ecKey->Assign(*copyKey);
                result = ecKey;
            } else {
                Scoped<EcPublicKey> ecKey(new EcPublicKey);
                ecKey->Assign(*copyKey);
                result = ecKey;
            }
        } else {
            THROW_EXCEPTION("Unsupported key type in use");
        }
        
        copyKey.Retain();
        
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
        
        LoadCertificate();
        LoadKeys();
        
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

void osx::Session::LoadCertificate() {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status = errSecSuccess;
        
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable();
        CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassCertificate);
        CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
        
        CFRef<CFArrayRef> result;
        status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&result);
        if (!status) {
            CFIndex itemsCount = CFArrayGetCount(*result);
            
            for (CFIndex index = 0; index < itemsCount; index++) {
                try {
                    SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(*result, index);
                    
                    X509Certificate x509;
                    x509.Assign(cert, false);
                    Scoped<std::string> x509Name = x509.GetName();
                    LOGGER_INFO("Reading certificate '%s'", x509Name->c_str());
                    
                    Scoped<core::PublicKey> publicKey = x509.GetPublicKey();
                    publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    
                    if (x509.HasPrivateKey()) {
                        Scoped<core::PrivateKey> privateKey = x509.GetPrivateKey();
                        privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                        objects.add(privateKey);
                        LOGGER_INFO("Private key was added");
                    }
                    objects.add(publicKey);
                    LOGGER_INFO("Public key was added");
                    
                    Scoped<X509Certificate> x509Copy = x509.Copy();
                    x509Copy->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    
                    
                    objects.add(x509Copy);
                    LOGGER_INFO("Certificate was added");
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
    CATCH_EXCEPTION
}

void osx::Session::LoadKeys() {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status = errSecSuccess;
        
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable();
        CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassKey);
        CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionaryAddValue(*matchAttr, kSecAttrLabel, kSecAttrLabelModule);
        CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(*matchAttr, kSecReturnAttributes, kCFBooleanTrue);
        
        CFRef<CFArrayRef> result;
        status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&result);
        if (!status) {
            CFIndex arrayCount = CFArrayGetCount(*result);
            
            for (CFIndex index = 0; index < arrayCount; index++) {
                try {
                    CFDictionaryRef attrs = (CFDictionaryRef)CFArrayGetValueAtIndex(*result, index);
                    SecKeyRef secKey = (SecKeyRef)CFDictionaryGetValue(attrs, kSecValueRef);
                    if (!secKey) {
                        LOGGER_ERROR("Cannot get SecKeyRef from attributes");
                        continue;
                    }
                    
                    // Don't add tokens which were added before
                    CK_LONG searchIndex = 0;
                    while (searchIndex < objects.count()) {
                        Scoped<core::Object> object = objects.items(searchIndex++);
                        osx::Key * key = dynamic_cast<osx::Key*>(object.get());
                        if (key && CFEqual(key->Get(), secKey)) {
                            break;
                        }
                    }
                    if (searchIndex < objects.count()) {
                        continue;
                    }
                    
                    Scoped<core::Object> key = SecKeyCopyObject(attrs);
                    key->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    
                    objects.add(key);
                }
                catch (Scoped<core::Exception> e) {
                    LOGGER_ERROR("Cannot load key. %s", e->what());
                }
            }
        }
    }
    CATCH_EXCEPTION
}
