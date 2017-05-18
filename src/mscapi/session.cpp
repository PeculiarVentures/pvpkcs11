#include "../core/excep.h"

#include "helper.h"
#include "session.h"
#include "crypto.h"

#include"rsa.h"
#include"ec.h"
#include"aes.h"

/*
#include "certificate.h"
#include "rsa_public_key.h"
#include "rsa_private_key.h"
#include "aes_key.h"
*/

using namespace mscapi;

Session::Session() : core::Session()
{
    digest = Scoped<CryptoDigest>(new CryptoDigest());
    sign = Scoped<CryptoSign>(new CryptoSign(CRYPTO_SIGN));
    verify = Scoped<CryptoSign>(new CryptoSign(CRYPTO_VERIFY));
    encrypt = Scoped<CryptoEncrypt>(new CryptoEncrypt(CRYPTO_ENCRYPT));
    decrypt = Scoped<CryptoEncrypt>(new CryptoEncrypt(CRYPTO_DECRYPT));
}

Session::~Session()
{
}

void Session::LoadMyStore()
{
    /*
    try {
        Scoped<crypt::CertStore> store(new crypt::CertStore());
        this->certStores.add(store);
        store->Open("My");
        Scoped<Collection<Scoped<crypt::X509Certificate>>> certs = store->GetCertificates();
        for (size_t i = 0; i < certs->count(); i++) {
            Scoped<crypt::X509Certificate> x509 = certs->items(i);
            Scoped<MscapiCertificate> x509Object(new MscapiCertificate(x509, true));

            // Get public key for Certificate. Application supports RSA and EC algorithms
            // In other case application throws error
            Scoped<Object> publicKeyObject;
            try {
                Scoped<crypt::Key> publicKey = x509->GetPublicKey();
                // fprintf(stdout, "Certificate '%s' has public key\n", x509->GetLabel()->c_str());
                Scoped<MscapiRsaPublicKey> key(new MscapiRsaPublicKey(publicKey, true));
                key->propId = *x509->GetHashPublicKey().get();
                publicKeyObject = key;
            }
            catch (Scoped<core::Exception> e) {
                continue;
            }

            // Get private key for Certificate
            Scoped<Object> privateKeyObject;
            if (x509->HasPrivateKey()) {
                // fprintf(stdout, "Certificate '%s' has private key\n", x509->GetLabel()->c_str());
                try {
                    Scoped<crypt::Key> privateKey = x509->GetPrivateKey();
                    Scoped<MscapiRsaPrivateKey> key(new MscapiRsaPrivateKey(privateKey, true));
                    key->id = *x509->GetHashPublicKey().get();
                    privateKeyObject = key;
                }
                catch (Scoped<core::Exception> e) {
                    // If we cannot get private key for certificate, we don't have to show this certificate in list
                    continue;
                }
            }

            this->objects.add(x509Object);
            this->objects.add(publicKeyObject);
            this->objects.add(privateKeyObject);
        }
    }
    CATCH_EXCEPTION;
    */
}

CK_RV Session::Open
(
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    try {
        // TestPrintContainers(PROV_RSA_AES);
        // TestCipher();

        CK_RV res = core::Session::Open(flags, pApplication, Notify, phSession);

        if (res == CKR_OK) {
            LoadMyStore();
        }
        return res;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::Close()
{
    try {
        CK_RV res = core::Session::Close();

        this->objects.clear();

        // close all opened stores
        /*
        for (size_t i = 0; i < this->certStores.count(); i++) {
            this->certStores.items(i)->Close();
        }
        */

        return res;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::GenerateKey
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

CK_RV Session::GenerateKeyPair
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

        Scoped<CryptoKeyPair> keyPair;
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

CK_RV mscapi::Session::GenerateRandom(
    CK_BYTE_PTR       pRandomData, /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    try {
        core::Session::GenerateRandom(pRandomData, ulRandomLen);

        NTSTATUS status = BCryptGenRandom(NULL, pRandomData, ulRandomLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::VerifyInit(
    CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
    CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    try {
        core::Session::VerifyInit(pMechanism, hKey);

        if (verify->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            verify = Scoped<CryptoSign>(new RsaPKCS1Sign(CRYPTO_VERIFY));
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            verify = Scoped<CryptoSign>(new RsaPSSSign(CRYPTO_VERIFY));
            break;
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            verify = Scoped<CryptoSign>(new EcDSASign(CRYPTO_VERIFY));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return verify->Init(pMechanism, GetObject(hKey));
    }
    CATCH_EXCEPTION
}

CK_RV Session::SignInit(
    CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
    try {
        core::Session::SignInit(pMechanism, hKey);

        if (sign->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            sign = Scoped<CryptoSign>(new RsaPKCS1Sign(CRYPTO_SIGN));
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            sign = Scoped<CryptoSign>(new RsaPSSSign(CRYPTO_SIGN));
            break;
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            sign = Scoped<CryptoSign>(new EcDSASign(CRYPTO_SIGN));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return sign->Init(pMechanism, GetObject(hKey));
    }
    CATCH_EXCEPTION
}

CK_RV Session::EncryptInit
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
        case CKM_RSA_PKCS_OAEP:
            encrypt = Scoped<CryptoRsaOAEPEncrypt>(new CryptoRsaOAEPEncrypt(CRYPTO_ENCRYPT));
            break;
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
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

CK_RV Session::DecryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
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
        case CKM_RSA_PKCS_OAEP:
            decrypt = Scoped<CryptoRsaOAEPEncrypt>(new CryptoRsaOAEPEncrypt(CRYPTO_DECRYPT));
            break;
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
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

CK_RV Session::DeriveKey
(
    CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
    CK_OBJECT_HANDLE     hBaseKey,          /* base key */
    CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
    CK_ULONG             ulAttributeCount,  /* template length */
    CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    try {
        core::Session::DeriveKey(
            pMechanism,
            hBaseKey,
            pTemplate,
            ulAttributeCount,
            phKey
        );

        auto baseKey = GetObject(hBaseKey);
        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulAttributeCount));

        Scoped<core::Object> derivedKey;
        switch (pMechanism->mechanism) {
        case CKM_ECDH1_DERIVE: {
            derivedKey = EcKey::DeriveKey(
                pMechanism,
                baseKey,
                tmpl
            );
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

Scoped<core::Object> Session::CreateObject
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
        case CKO_PUBLIC_KEY:
            switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
            case CKK_RSA:
                object = Scoped<RsaPublicKey>(new RsaPublicKey());
                break;
            case CKK_EC:
                object = Scoped<EcPublicKey>(new EcPublicKey());
                break;
            default:
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            break;
        default:
            THROW_PKCS11_TEMPLATE_INCOMPLETE();
        }

        object->CreateValues(pTemplate, ulCount);

        return object;
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> Session::CopyObject
(
    Scoped<core::Object> object,      /* the object for copying */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
    CK_ULONG             ulCount      /* attributes in template */
)
{
    try {
        Scoped<core::Object> copy;

        if (dynamic_cast<AesKey*>(object.get())) {
            copy = Scoped<AesKey>(new AesKey());
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object is not copyable");
        }
        copy->CopyValues(object, pTemplate, ulCount);
        return copy;
    }
    CATCH_EXCEPTION
}