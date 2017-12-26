#include "sys_session.h"

#include "../core/excep.h"

#include "helper.h"
#include "crypto.h"

#include "rsa.h"
#include "ec.h"
#include "aes.h"

#include "ncrypt/provider.h"

#include "certificate.h"
#include "data.h"

#include "Winscard.h"
#include "scard.h"

using namespace mscapi;

void test() {
    LOGGER_FUNCTION_BEGIN;

    try {
        scard::Context context;
        context.Initialize(SCARD_SCOPE_SYSTEM);

        auto readers = context.GetReaders();
        for (int i = 0; i < readers.size(); i++) {
            auto reader = readers.at(i);
            printf("Reader: %s\n", reader->name->c_str());
            try {
                reader->Connect(SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1);
                auto atr = reader->GetAttributeBytes(SCARD_ATTR_ATR_STRING);
                auto cards = context.GetCards(atr);
                for (int j = 0; j < cards.size(); j++) {
                    auto card = cards.at(j);
                    auto csp = card->GetProviderName(SCARD_PROVIDER_CSP);
                    printf("CSP: %s\n", csp->c_str());
                    auto ksp = card->GetProviderName(SCARD_PROVIDER_KSP);
                    printf("KSP: %s\n", ksp->c_str());
                }
                reader->Disconnect();
            }
            catch (Scoped<core::Exception> e) {
                if (e->name.compare(SCARD_EXCEPTION_NAME) == 0) {
                    MscapiException* msException = (MscapiException*)e.get();
                    if (msException->code != SCARD_W_REMOVED_CARD) {
                        throw e;
                    }
                }
                else {
                    throw e;
                }
            }
        }
    }
    CATCH_EXCEPTION
}

void test2() {
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = ERROR_SUCCESS;
        SCARDCONTEXT hContext;
        SCARDHANDLE hCard;
        PBYTE atr;
        std::string readers;
        LPSTR pmszReaders = NULL, pReader, mszCards = NULL, pCard, szProvider = NULL, szContainer;
        DWORD dwLen = SCARD_AUTOALLOCATE, dwAtrLen;

        status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &hContext);
        if (status != SCARD_S_SUCCESS) {
            THROW_NT_EXCEPTION(status, "SCardEstablishContext");
        }

        status = SCardListReaders(hContext, SCARD_ALL_READERS, NULL, &dwLen);
        if (status != SCARD_S_SUCCESS) {
            THROW_NT_EXCEPTION(status, "SCardListReaders");
        }

        readers.resize(dwLen);

        status = SCardListReaders(hContext, SCARD_ALL_READERS, (LPSTR)readers.c_str(), &dwLen);
        if (status != SCARD_S_SUCCESS) {
            THROW_NT_EXCEPTION(status, "SCardListReaders");
        }

        puts("Here");
        // Do something with the multi string of readers.
        // Output the values.
        // A double-null terminates the list of values.
        pReader = (LPSTR)readers.c_str();
        while ('\0' != *pReader)
        {
            // Display the value.
            // printf("Reader: %s\n", pReader);

            status = SCardConnect(hContext, pReader, SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &hCard, &dwLen);
            if (status == SCARD_S_SUCCESS) {
                puts("Card connected");
            }

            dwLen = SCARD_AUTOALLOCATE;
            status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_CSP, NULL, &dwLen);
            if (status != SCARD_S_SUCCESS) {
                THROW_NT_EXCEPTION(status, "SCardGetCardTypeProviderName");
            }
            std::string provider;
            provider.resize(dwLen);
            szProvider = (char *)provider.c_str();
            status = SCardGetCardTypeProviderName(hContext, pCard, SCARD_PROVIDER_CSP, szProvider, &dwLen);
            if (status != SCARD_S_SUCCESS) {
                THROW_NT_EXCEPTION(status, "SCardGetCardTypeProviderName");
            }
            printf("Provider: %s\n", provider.c_str());

            // Advance to the next value.
            pReader = pReader + strlen(pReader) + 1;
        }

        // Free the memory.
        SCardFreeMemory(hContext, pmszReaders);
    }
    CATCH_EXCEPTION
}

SystemSession::SystemSession() : mscapi::Session()
{
}

SystemSession::~SystemSession()
{
}

void SystemSession::LoadMyStore()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        LOGGER_INFO("%s Reading My storage", __FUNCTION__);
        Scoped<crypt::CertificateStorage> store(new crypt::CertificateStorage());
        this->certStores.push_back(store);
        store->Open(PV_STORE_NAME_MY);
        auto certs = store->GetCertificates();

        for (size_t i = 0; i < certs->size(); i++) {
            Scoped<std::string> certName(new std::string("unknown"));
            try {
                auto cert = certs->at(i);
                certName = cert->GetName();

                LOGGER_INFO("%s Reading certificate '%s'", __FUNCTION__, certName->c_str());

                if (!cert->HasPrivateKey()) {
                    THROW_EXCEPTION("Certificate '%s' doesn't have private key", certName->c_str());
                }

#pragma region Fill certificate data
                Scoped<X509Certificate> x509(new X509Certificate());
                x509->Assign(cert);

                x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                x509->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                x509->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                Scoped<core::Object> publicKey = x509->GetPublicKey();
                Scoped<core::Object> privateKey = x509->GetPrivateKey();

#pragma endregion
                LOGGER_INFO("%s Add certificate '%s'", __FUNCTION__, certName->c_str());
                this->objects.add(x509);

                if (privateKey.get() && publicKey.get()) {
                    privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);

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

void SystemSession::LoadRequestStore()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<crypt::CertificateStorage> requestStore(new crypt::CertificateStorage);
        requestStore->Open(PV_STORE_NAME_REQUEST);

        auto certs = requestStore->GetCertificates();

        for (ULONG i = 0; i < certs->size(); i++) {
            try {
                auto cert = certs->at(i);
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

void SystemSession::LoadCngKeys()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        auto keyNames = provider->GetKeyNames(0);
        for (ULONG i = 0; i < keyNames->size(); i++) {
            try {
                Scoped<core::Object> privateKey;
                Scoped<core::Object> publicKey;
                auto keyName = keyNames->at(i);
                auto key = provider->GetKey(keyName->pszName, keyName->dwLegacyKeySpec, keyName->dwFlags);

#pragma region Fill publicKey and privateKey
                auto propAlgGroup = key->GetStringW(NCRYPT_ALGORITHM_GROUP_PROPERTY);

                if (propAlgGroup->compare(NCRYPT_RSA_ALGORITHM_GROUP) == 0) {
                    auto rsaPrivateKey = Scoped<RsaPrivateKey>(new RsaPrivateKey());
                    rsaPrivateKey->SetKey(key);
                    auto rsaPublicKey = Scoped<RsaPublicKey>(new RsaPublicKey());
                    rsaPublicKey->SetKey(key);
                    privateKey = rsaPrivateKey;
                    publicKey = rsaPublicKey;
                }
                else if (propAlgGroup->compare(NCRYPT_ECDH_ALGORITHM_GROUP) == 0 ||
                    propAlgGroup->compare(NCRYPT_ECDSA_ALGORITHM_GROUP) == 0) {
                    auto ecPrivateKey = Scoped<EcPrivateKey>(new EcPrivateKey());
                    ecPrivateKey->SetKey(key);
                    auto ecPublicKey = Scoped<EcPublicKey>(new EcPublicKey());
                    ecPublicKey->SetKey(key);
                    privateKey = ecPrivateKey;
                    publicKey = ecPublicKey;
                }
                else {
                    LOGGER_DEBUG("%s Unsupported algorithm %s", __FUNCTION__, propAlgGroup->c_str());
                    continue;
                }
#pragma endregion

                auto attrID = key->GetID();
                auto objCount = objects.count();
                int j = 0;

#pragma region Add public key, if not exist in objects
                for (j = 0; j < objCount; j++) {
                    Scoped<core::Object> obj = objects.items(j);
                    if (obj->ItemByType(CKA_CLASS)->ToNumber() == CKO_PUBLIC_KEY &&
                        obj->ItemByType(CKA_KEY_TYPE)->ToNumber() == publicKey->ItemByType(CKA_KEY_TYPE)->ToNumber() &&
                        memcmp(obj->ItemByType(CKA_ID)->ToBytes()->data(), attrID->data(), attrID->size()) == 0) {
                        break;
                    }
                }

                if (j == objCount) {
                    privateKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                    privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    privateKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                    privateKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                    LOGGER_DEBUG("%s Add public key", __FUNCTION__);
                    objects.add(publicKey);
                }
#pragma endregion

#pragma region Add private key, if not exist in objects
                for (j = 0; j < objCount; j++) {
                    Scoped<core::Object> obj = objects.items(j);
                    if (obj->ItemByType(CKA_CLASS)->ToNumber() == CKO_PRIVATE_KEY &&
                        obj->ItemByType(CKA_KEY_TYPE)->ToNumber() == privateKey->ItemByType(CKA_KEY_TYPE)->ToNumber() &&
                        memcmp(obj->ItemByType(CKA_ID)->ToBytes()->data(), attrID->data(), attrID->size()) == 0) {
                        break;
                    }
                }

                if (j == objCount) {
                    publicKey->ItemByType(CKA_ID)->SetValue(attrID->data(), attrID->size());
                    publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    publicKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                    publicKey->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                    LOGGER_DEBUG("%s Add private key", __FUNCTION__);
                    objects.add(privateKey);
                }
#pragma endregion
            }
            catch (Scoped<core::Exception> e) {
                LOGGER_DEBUG("%s Cannot load CNG key. %s", __FUNCTION__, e->what());
            }
            catch (...) {
                LOGGER_DEBUG("%s Cannot load CNG key. Unknown error", __FUNCTION__);
            }
        }
    }
    CATCH_EXCEPTION
}

CK_RV SystemSession::Open
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

        test();

        if (res == CKR_OK) {
            LoadMyStore();
            LoadRequestStore();
            LoadCngKeys();
        }
        return res;
    }
    CATCH_EXCEPTION;
}

CK_RV SystemSession::Close()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CK_RV res = core::Session::Close();

        this->objects.clear();

        return res;
    }
    CATCH_EXCEPTION;
}

CK_RV SystemSession::GenerateKey
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

CK_RV SystemSession::GenerateKeyPair
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

Scoped<core::Object> mscapi::SystemSession::CreateObject
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

Scoped<core::Object> mscapi::SystemSession::CopyObject
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