#include "../core/excep.h"

#include "helper.h"
#include "session.h"
#include "crypto.h"

#include "rsa.h"
#include "ec.h"
#include "aes.h"

#include "certificate.h"
#include "data.h"

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
    LOGGER_FUNCTION_BEGIN;

    try {
        LOGGER_INFO("%s Reading My storage", __FUNCTION__);
        Scoped<crypt::CertStore> store(new crypt::CertStore());
        this->certStores.push_back(store);
        store->Open(PV_STORE_NAME_MY);
        auto certs = store->GetCertificates();

        for (size_t i = 0; i < certs.size(); i++) {
            Scoped<std::string> certName(new std::string("unknown"));
            try {
                auto cert = certs.at(i);
                certName = cert->GetName();

                LOGGER_INFO("%s Reading certificate '%s'", __FUNCTION__, certName->c_str());

                if (!cert->HasProperty(CERT_KEY_PROV_INFO_PROP_ID)) {
                    LOGGER_INFO("%s Certificate '%s' doesn't have CERT_KEY_PROV_INFO_PROP_ID. Skip certificate.", __FUNCTION__, certName->c_str());
                    continue;
                }

                auto propKeyProvInfo = cert->GetPropertyBytes(CERT_KEY_PROV_INFO_PROP_ID);
                CRYPT_KEY_PROV_INFO* pKeyProvInfo = (CRYPT_KEY_PROV_INFO*)propKeyProvInfo->data();

                Scoped<core::Object> privateKey;
                Scoped<core::Object> publicKey;

#pragma region CNG provider
                if (pKeyProvInfo->dwProvType == 0) {
                    // CNG
                    if (!wmemcmp(MS_KEY_STORAGE_PROVIDER, pKeyProvInfo->pwszProvName, lstrlenW(MS_KEY_STORAGE_PROVIDER))) {
                        // Get all CNG keys via LoadCngKeys
                        LOGGER_INFO("%s Certificate '%s' has CNG key", __FUNCTION__, certName->c_str());
                    }
                    else {
                        LOGGER_INFO("%s Certificate '%s' is not MS_KEY_STORAGE_PROVIDER. Skip certificate.", __FUNCTION__, certName->c_str());
                        continue;
                    }
                }
#pragma endregion
#pragma region CAPI provider
                else if (
                    pKeyProvInfo->dwProvType == PROV_RSA_FULL ||
                    pKeyProvInfo->dwProvType == PROV_RSA_AES ||
                    pKeyProvInfo->dwProvType == PROV_RSA_SIG ||
                    pKeyProvInfo->dwProvType == PROV_EC_ECDSA_FULL ||
                    pKeyProvInfo->dwProvType == PROV_EC_ECDSA_SIG
                    ) {
                    // CAPI
                    LOGGER_INFO("%s Certificate '%s' has CAPI key", __FUNCTION__, certName->c_str());
                    Scoped<crypt::Provider> provider(new crypt::Provider());
                    try {
                        provider->AcquireContextW(
                            pKeyProvInfo->pwszContainerName,
                            pKeyProvInfo->pwszProvName,
                            pKeyProvInfo->dwProvType,
                            CRYPT_SILENT
                        );
                    }
                    catch (Scoped<core::Exception> e) {
                        // cannot get key. it can be on smart card
                        LOGGER_ERROR("%s Cannot acquire key content for certificate '%s'.", __FUNCTION__, certName->c_str());
                        LOGGER_ERROR("%s %s", __FUNCTION__, e->message.c_str());
                        LOGGER_INFO("%s Skip certificate '%s'.", __FUNCTION__, certName->c_str());
                        continue;
                    }
                    Scoped<ncrypt::Provider> nprov(new ncrypt::Provider());

                    nprov->Open(MS_KEY_STORAGE_PROVIDER, 0);
                    auto key = provider->GetUserKey(pKeyProvInfo->dwKeySpec);

                    Scoped<ncrypt::Key> nkey;
                    try {
                        nkey = nprov->TranslateHandle(provider->Get(), key->Get(), 0, 0);
                    }
                    catch (...) {
                        try {
                            // Rutoken throws C0000225 error on NCryptTranslateHandle
                            nprov->Open(MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
                            nkey = nprov->OpenKey(pKeyProvInfo->pwszContainerName, pKeyProvInfo->dwKeySpec, 0);
                        }
                        catch (Scoped<core::Exception> e) {
                            // Don't use this key
                            LOGGER_ERROR("%s Cannot get key. May be wrong Provider", __FUNCTION__);
                            LOGGER_ERROR("%s %s", __FUNCTION__, e->message.c_str());
                            LOGGER_INFO("%s Skip certificate '%s'.", __FUNCTION__, certName->c_str());
                            continue;
                        }
                    }

                    try {
                        switch (pKeyProvInfo->dwProvType) {
                        case PROV_RSA_SIG:
                        case PROV_RSA_AES:
                        case PROV_RSA_FULL: {
                            auto rsaPrivateKey = Scoped<RsaPrivateKey>(new RsaPrivateKey());
                            rsaPrivateKey->Assign(nkey);
                            auto rsaPublicKey = Scoped<RsaPublicKey>(new RsaPublicKey());
                            rsaPublicKey->Assign(nkey);
                            privateKey = rsaPrivateKey;
                            publicKey = rsaPublicKey;
                            break;
                        }
                        case PROV_EC_ECDSA_SIG:
                        case PROV_EC_ECDSA_FULL:
                            auto ecPrivateKey = Scoped<EcPrivateKey>(new EcPrivateKey());
                            ecPrivateKey->Assign(nkey);
                            auto ecPublicKey = Scoped<EcPublicKey>(new EcPublicKey());
                            ecPublicKey->Assign(nkey);
                            privateKey = ecPrivateKey;
                            publicKey = ecPublicKey;
                            break;
                        }
                    }
                    catch (Scoped<core::Exception> e) {
                        // Cannot get key
                        LOGGER_ERROR("%s Cannot get key pwszContainerName:%s", __FUNCTION__, pKeyProvInfo->pwszContainerName);
                        LOGGER_ERROR("%s %s", __FUNCTION__, e->what());
                    }
                }
#pragma endregion
#pragma region others
                else {
                    LOGGER_DEBUG("%s Unsupported dwProvType %d", __FUNCTION__, pKeyProvInfo->dwProvType);
                    LOGGER_DEBUG("%s Skip certificate '%s'.", __FUNCTION__, certName->c_str());
                    continue;
                }
#pragma endregion

#pragma region Fill certificate data
                Scoped<X509Certificate> x509(new X509Certificate());
                x509->Assign(cert);

                x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                x509->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                x509->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);
#pragma endregion
                LOGGER_INFO("%s Add certificate '%s'", __FUNCTION__, certName->c_str());
                this->objects.add(x509);

                if (privateKey && publicKey) {
#pragma region Fill keys data
                    auto attrID = x509->ItemByType(CKA_ID)->To<core::AttributeBytes>()->ToValue();
                    privateKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                    privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    privateKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                    privateKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                    publicKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                    publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    publicKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                    publicKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);
#pragma endregion
                    LOGGER_INFO("%s Add public key", __FUNCTION__);
                    this->objects.add(publicKey);
                    LOGGER_INFO("%s Add private key", __FUNCTION__);
                    this->objects.add(privateKey);
                }
            }
            catch (Scoped<core::Exception> e) {
                LOGGER_ERROR("%s Cannot load certificate '%s'. %s", __FUNCTION__, certName->c_str(), e->what());
            }
            catch (...) {
                LOGGER_ERROR("%s Cannot load certificate '%s'. Uknown error", __FUNCTION__, certName->c_str());
            }
        }
    }
    CATCH_EXCEPTION
}

void Session::LoadRequestStore()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<crypt::CertStore> requestStore(new crypt::CertStore());
        requestStore->Open(PV_STORE_NAME_REQUEST);

        auto certs = requestStore->GetCertificates();

        for (ULONG i = 0; i < certs.size(); i++) {
            try {
                auto cert = certs.at(i);
                if (cert->HasProperty(CERT_PV_REQUEST) && cert->HasProperty(CERT_PV_ID)) {
                    Scoped<X509CertificateRequest> object(new X509CertificateRequest());
                    object->Assign(cert);

                    object->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    object->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                    object->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                    objects.add(object);
                }
            }
            catch (Scoped<core::Exception> e) {
                LOGGER_DEBUG("Cannot load request from store. %s", e->what());
            }
            catch (...) {
                LOGGER_DEBUG("Cannot load request from store. Unknown exception");
            }
        }

        certStores.push_back(requestStore);
    }
    CATCH_EXCEPTION
}

void Session::LoadCngKeys()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        auto keyNames = provider->GetKeyNames(0);
        for (ULONG i = 0; i < keyNames->size(); i++) {
            try {
                auto keyName = keyNames->at(i);
                auto key = provider->OpenKey(keyName->pszName, keyName->dwLegacyKeySpec, keyName->dwFlags);
                auto propAlgGroup = key->GetBytesW(NCRYPT_ALGORITHM_GROUP_PROPERTY);
                Scoped<core::Object> privateKey;
                Scoped<core::Object> publicKey;
                if (!wmemcmp(propAlgGroup->c_str(), NCRYPT_RSA_ALGORITHM_GROUP, lstrlenW(NCRYPT_RSA_ALGORITHM_GROUP))) {
                    auto rsaPrivateKey = Scoped<RsaPrivateKey>(new RsaPrivateKey());
                    rsaPrivateKey->Assign(key);
                    auto rsaPublicKey = Scoped<RsaPublicKey>(new RsaPublicKey());
                    rsaPublicKey->Assign(key);
                    privateKey = rsaPrivateKey;
                    publicKey = rsaPublicKey;
                }
                else if (!wmemcmp(propAlgGroup->c_str(), NCRYPT_ECDH_ALGORITHM_GROUP, lstrlenW(NCRYPT_ECDH_ALGORITHM_GROUP)) ||
                    !wmemcmp(propAlgGroup->c_str(), NCRYPT_ECDSA_ALGORITHM_GROUP, lstrlenW(NCRYPT_ECDSA_ALGORITHM_GROUP))) {
                    auto ecPrivateKey = Scoped<EcPrivateKey>(new EcPrivateKey());
                    ecPrivateKey->Assign(key);
                    auto ecPublicKey = Scoped<EcPublicKey>(new EcPublicKey());
                    ecPublicKey->Assign(key);
                    privateKey = ecPrivateKey;
                    publicKey = ecPublicKey;
                }
                else {
                    LOGGER_DEBUG("%s Unsupported algorithm %s", __FUNCTION__, propAlgGroup->c_str());
                    continue;
                }

                auto attrID = key->GetId();
                privateKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                privateKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                privateKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                publicKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                publicKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                publicKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                LOGGER_DEBUG("%s Add public key", __FUNCTION__);
                objects.add(publicKey);
                LOGGER_DEBUG("%s Add private key", __FUNCTION__);
                objects.add(privateKey);
            }
            catch (Scoped<core::Exception> e) {
                LOGGER_DEBUG("%s Cannot load CNG key. %s",__FUNCTION__, e->what());
            }
            catch (...) {
                LOGGER_DEBUG("%s Cannot load CNG key. Unknown error", __FUNCTION__);
            }
        }
    }
    CATCH_EXCEPTION
}

CK_RV Session::Open
(
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CK_RV res = core::Session::Open(flags, pApplication, Notify, phSession);

        if (res == CKR_OK) {
            LoadMyStore();
            LoadRequestStore();
            LoadCngKeys();
        }
        return res;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::Close()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CK_RV res = core::Session::Close();

        this->objects.clear();

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

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
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Template tmpl(pTemplate, ulCount);
        Scoped<core::Object> object;
        auto ckaClass = tmpl.GetNumber(CKA_CLASS, true);
        switch (ckaClass) {
        case CKO_SECRET_KEY:
            switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
            case CKK_AES:
                object = Scoped<AesKey>(new AesKey());
                break;
            default:
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            break;
        case CKO_PRIVATE_KEY:
            switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
            case CKK_RSA:
                object = Scoped<RsaPrivateKey>(new RsaPrivateKey());
                break;
            case CKK_EC:
                object = Scoped<EcPrivateKey>(new EcPrivateKey());
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
        case CKO_DATA: {
            object = Scoped<X509CertificateRequest>(new X509CertificateRequest());
            break;
        }
        case CKO_CERTIFICATE: {
            object = Scoped<X509Certificate>(new X509Certificate());
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

Scoped<core::Object> Session::CopyObject
(
    Scoped<core::Object> object,      /* the object for copying */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
    CK_ULONG             ulCount      /* attributes in template */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<core::Object> copy;
        if (dynamic_cast<RsaPrivateKey*>(object.get())) {
            copy = Scoped<RsaPrivateKey>(new RsaPrivateKey());
        }
        else if (dynamic_cast<RsaPublicKey*>(object.get())) {
            copy = Scoped<RsaPublicKey>(new RsaPublicKey());
        }
        else if (dynamic_cast<EcPrivateKey*>(object.get())) {
            copy = Scoped<EcPrivateKey>(new EcPrivateKey());
        }
        else if (dynamic_cast<EcPublicKey*>(object.get())) {
            copy = Scoped<EcPublicKey>(new EcPublicKey());
        }
        else if (dynamic_cast<EcPrivateKey*>(object.get())) {
            copy = Scoped<EcPrivateKey>(new EcPrivateKey());
        }
        else if (dynamic_cast<X509Certificate*>(object.get())) {
            copy = Scoped<X509Certificate>(new X509Certificate());
        }
        else if (dynamic_cast<X509CertificateRequest*>(object.get())) {
            copy = Scoped<X509CertificateRequest>(new X509CertificateRequest());
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object is not copyable");
        }

        copy->CopyValues(object, pTemplate, ulCount);
        return copy;
    }
    CATCH_EXCEPTION
}