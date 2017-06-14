#include "session.h"

#include "../core/crypto.h"

#include "crypto.h"
#include "aes.h"
#include "rsa.h"
#include "ec.h"

#include "certificate.h"
#include "x509_template.h"
#include "helper.h"
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>

using namespace osx;

Scoped<core::Object> osx::Session::CreateObject
(
 CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
 CK_ULONG                ulCount      /* attributes in template */
)
{
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
    try {
        Scoped<core::Object> copy;
        if (dynamic_cast<X509Certificate*>(object.get())) {
            copy = Scoped<X509Certificate>(new X509Certificate());
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
    try {
        core::Session::Open(
                            flags,
                            pApplication,
                            Notify,
                            phSession
                            );
        
        digest = Scoped<CryptoDigest>(new CryptoDigest());
        encrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_ENCRYPT));
        decrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_DECRYPT));
        sign = Scoped<core::CryptoSign>(new core::CryptoSign(CRYPTO_SIGN));
        verify = Scoped<core::CryptoSign>(new core::CryptoSign(CRYPTO_VERIFY));
        
        OSStatus status;
        
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(
                                                                            kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecClass, kSecClassCertificate);
        CFDictionaryAddValue(&matchAttr, kSecMatchLimit, kSecMatchLimitAll);
        CFDictionaryAddValue(&matchAttr, kSecReturnRef, kCFBooleanTrue);
        
        CFArrayRef result;
        status = SecItemCopyMatching(&matchAttr, (CFTypeRef*)&result);
        if (status) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Error on SecItemCopyMatching");
        }
        CFRef<CFArrayRef> scopedResult(result);
        auto certCount = CFArrayGetCount(result);
        
        CFIndex index = 0;
        while (index < certCount) {
            SecCertificateRef cert = (SecCertificateRef)CFArrayGetValueAtIndex(result, index++);
            CFRef<CFDataRef> certData = SecCertificateCopyData(cert);
            SecCertificateRef certCopy = SecCertificateCreateWithData(NULL, &certData);
            
            Scoped<X509Certificate> x509(new X509Certificate);
            x509->Assign(certCopy);
            x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
            
            auto publicKey = x509->GetPublicKey();
            publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
            
            if (x509->HasPrivateKey()) {
                Scoped<core::PrivateKey> privateKey = x509->GetPrivateKey();
                privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                objects.add(privateKey);
            }
            
            objects.add(x509);
            objects.add(publicKey);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Close()
{
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::GenerateRandom(
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
        
        auto baseKey = GetObject(hBaseKey);
        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulAttributeCount));
        
        Scoped<core::Object> derivedKey;
        switch (pMechanism->mechanism) {
            case CKM_ECDH1_DERIVE: {
                derivedKey = EcKey::DeriveKey(pMechanism,
                                              baseKey,
                                              tmpl);
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
