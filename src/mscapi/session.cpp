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

void Test()
{
    try {
        ncrypt::Provider provider;
        provider.Open(MS_KEY_STORAGE_PROVIDER, 0);
        auto key = provider.CreatePersistedKey(NCRYPT_RSA_ALGORITHM, L"test RSA key", 0, NCRYPT_OVERWRITE_KEY_FLAG);
        key->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, NCRYPT_ALLOW_SIGNING_FLAG);
        key->SetNumber(NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_PERSIST_FLAG);
        key->Finalize();

        LPCTSTR pszX500 = "CN = CNG Certificate #1";

        DWORD cbEncoded = 0;

        if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, NULL, &cbEncoded, NULL)) {
            THROW_MSCAPI_EXCEPTION();
        }
        PUCHAR pbEncoded = (PUCHAR)malloc(cbEncoded);
        if (!CertStrToName(X509_ASN_ENCODING, pszX500, CERT_X500_NAME_STR, NULL, pbEncoded, &cbEncoded, NULL)) {
            THROW_MSCAPI_EXCEPTION();
        }

        CERT_NAME_BLOB nameBlob;
        nameBlob.pbData = pbEncoded;
        nameBlob.cbData = cbEncoded;

        // Prepare key provider structure for self-signed certificate

        CRYPT_KEY_PROV_INFO KeyProvInfo;

        KeyProvInfo.pwszContainerName = L"test RSA key";

        KeyProvInfo.pwszProvName = MS_KEY_STORAGE_PROVIDER;

        KeyProvInfo.dwProvType = 0;

        KeyProvInfo.dwFlags = 0;

        KeyProvInfo.cProvParam = 0;

        KeyProvInfo.rgProvParam = NULL;

        KeyProvInfo.dwKeySpec = 0;


        // Prepare algorithm structure for self-signed certificate

        CRYPT_ALGORITHM_IDENTIFIER SignatureAlgorithm;

        SignatureAlgorithm.pszObjId = szOID_RSA_SHA1RSA;


        // Prepare Expiration date for self-signed certificate

        SYSTEMTIME EndTime;

        GetSystemTime(&EndTime);

        EndTime.wYear += 5;

        PCCERT_CONTEXT pCertContext = CertCreateSelfSignCertificate(key->Get(), &nameBlob, 0, &KeyProvInfo, &SignatureAlgorithm, 0, &EndTime, 0);
        if (!pCertContext) {
            THROW_MSCAPI_EXCEPTION();
        }
        Scoped<crypt::Certificate> cert(new crypt::Certificate);
        cert->Assign(pCertContext);

        crypt::CertStore store;
        store.Open("My");
        store.AddCertificate(cert, CERT_STORE_ADD_NEW);
    }
    CATCH_EXCEPTION
}

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
    try {
        Scoped<crypt::CertStore> store(new crypt::CertStore());
        this->certStores.push_back(store);
        store->Open(PV_STORE_NAME_MY);
        auto certs = store->GetCertificates();
        for (size_t i = 0; i < certs.size(); i++) {
            auto cert = certs.at(i);

            if (!cert->HasProperty(CERT_KEY_PROV_INFO_PROP_ID)) {
                continue;
            }

            auto propKeyProvInfo = cert->GetPropertyBytes(CERT_KEY_PROV_INFO_PROP_ID);
            CRYPT_KEY_PROV_INFO* pKeyProvInfo = (CRYPT_KEY_PROV_INFO*)propKeyProvInfo->data();

            Scoped<core::Object> privateKey;
            Scoped<core::Object> publicKey;
            if (
                pKeyProvInfo->dwProvType == 0 &&
                !wmemcmp(MS_KEY_STORAGE_PROVIDER, pKeyProvInfo->pwszProvName, lstrlenW(MS_KEY_STORAGE_PROVIDER))
                ) {
                // CNG
                // Get all CNG keys via LoadCngKeys
            }
            else if (
                pKeyProvInfo->dwProvType == PROV_RSA_FULL ||
                pKeyProvInfo->dwProvType == PROV_RSA_AES ||
                pKeyProvInfo->dwProvType == PROV_RSA_SIG ||
                pKeyProvInfo->dwProvType == PROV_EC_ECDSA_FULL ||
                pKeyProvInfo->dwProvType == PROV_EC_ECDSA_SIG
                ) {
                // CAPI
                Scoped<crypt::Provider> provider(new crypt::Provider());
                try {
                    provider->AcquireContextW(
                        pKeyProvInfo->pwszContainerName,
                        pKeyProvInfo->pwszProvName,
                        pKeyProvInfo->dwProvType,
                        CRYPT_SILENT
                    );
                }
                catch (...) {
                    // cannot get key. it can be on smart card
                    continue;
                }
                auto key = provider->GetUserKey(pKeyProvInfo->dwKeySpec);

                Scoped<ncrypt::Provider> nprov(new ncrypt::Provider());
                nprov->Open(MS_KEY_STORAGE_PROVIDER, 0);
                auto nkey = nprov->TranslateHandle(provider->Get(), key->Get(), 0, 0);

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
            else {
                continue;
            }

            Scoped<X509Certificate> x509(new X509Certificate());
            x509->Assign(cert);

            x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
            x509->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
            x509->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

            this->objects.add(x509);

            if (privateKey && publicKey) {
                auto attrID = x509->ItemByType(CKA_ID)->To<core::AttributeBytes>()->ToValue();
                privateKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                privateKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                privateKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                publicKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                publicKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                publicKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                this->objects.add(publicKey);
                this->objects.add(privateKey);
            }
        }
    }
    CATCH_EXCEPTION
}

void Session::LoadRequestStore()
{
    try {
        Scoped<crypt::CertStore> requestStore(new crypt::CertStore());
        requestStore->Open(PV_STORE_NAME_REQUEST);

        auto certs = requestStore->GetCertificates();

        for (ULONG i = 0; i < certs.size(); i++) {
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
    }
    CATCH_EXCEPTION
}

void Session::LoadCngKeys()
{
    try {
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        auto keyNames = provider->GetKeyNames(0);
        for (ULONG i = 0; i < keyNames->size(); i++) {
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
            } else if (!wmemcmp(propAlgGroup->c_str(), NCRYPT_ECDH_ALGORITHM_GROUP, lstrlenW(NCRYPT_ECDH_ALGORITHM_GROUP)) ||
                !wmemcmp(propAlgGroup->c_str(), NCRYPT_ECDSA_ALGORITHM_GROUP, lstrlenW(NCRYPT_ECDSA_ALGORITHM_GROUP))) {
                auto ecPrivateKey = Scoped<EcPrivateKey>(new EcPrivateKey());
                ecPrivateKey->Assign(key);
                auto ecPublicKey = Scoped<EcPublicKey>(new EcPublicKey());
                ecPublicKey->Assign(key);
                privateKey = ecPrivateKey;
                publicKey = ecPublicKey;
            }
            else {
                // Unsupported algorithm
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

            objects.add(publicKey);
            objects.add(privateKey);
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
    try {

        // Test();

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