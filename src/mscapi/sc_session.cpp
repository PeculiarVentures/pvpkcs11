#include <winscard.h>
#include "sc_session.h"

#include "ncrypt/provider.h"

#include "rsa.h"
#include "ec.h"
#include "aes.h"

using namespace mscapi;

mscapi::SmartCardSession::SmartCardSession(
    PCCH  readerName,
    PCCH  provName,
    DWORD provType
) :
    Session(),
    readerName(Scoped<std::string>(new std::string(readerName))),
    provName(Scoped<std::string>(new std::string(provName))),
    provType(provType)
{
}

mscapi::SmartCardSession::~SmartCardSession()
{
}

CK_RV mscapi::SmartCardSession::Open(
    CK_FLAGS                flags,
    CK_VOID_PTR             pApplication,
    CK_NOTIFY               Notify,
    CK_SESSION_HANDLE_PTR   phSession
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CK_RV res = core::Session::Open(flags, pApplication, Notify, phSession);

        LoadProvider();

        return res;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::SmartCardSession::GenerateKeyPair(
    CK_MECHANISM_PTR        pMechanism,
    CK_ATTRIBUTE_PTR        pPublicKeyTemplate,
    CK_ULONG                ulPublicKeyAttributeCount,
    CK_ATTRIBUTE_PTR        pPrivateKeyTemplate,
    CK_ULONG                ulPrivateKeyAttributeCount,
    CK_OBJECT_HANDLE_PTR    phPublicKey,
    CK_OBJECT_HANDLE_PTR    phPrivateKey
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
    CATCH_EXCEPTION
}

Scoped<core::Object> mscapi::SmartCardSession::CreateObject(
    CK_ATTRIBUTE_PTR    pTemplate,
    CK_ULONG            ulCount
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Template tmpl(pTemplate, ulCount);
        Scoped<core::Object> object;

        std::wstring wstrProvName(provName->begin(), provName->end());
        std::wstring wstrReaderName(readerName->begin(), readerName->end());
        std::wstring wstrScope = L"";
        wstrScope += L"\\\\.\\";
        wstrScope += wstrReaderName.c_str();
        wstrScope += L"\\";

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
                object = Scoped<RsaPublicKey>(new RsaPublicKey(
                    (LPWSTR)wstrProvName.c_str(),
                    provType == SCARD_PROVIDER_KSP ? 0 : PROV_RSA_FULL,
                    (LPWSTR)wstrScope.c_str()
                ));
                break;
            case CKK_EC:
                object = Scoped<EcPublicKey>(new EcPublicKey(
                    (LPWSTR)wstrProvName.c_str(),
                    provType == SCARD_PROVIDER_KSP ? 0 : PROV_EC_ECDSA_FULL,
                    (LPWSTR)wstrScope.c_str()
                ));
                break;
            default:
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            break;
        case CKO_CERTIFICATE: {
            object = Scoped<X509Certificate>(new X509Certificate(
                (LPWSTR)wstrProvName.c_str(),
                provType,
                (LPWSTR)wstrScope.c_str()
            ));
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

Scoped<core::Object> mscapi::SmartCardSession::CopyObject(Scoped<core::Object> object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<core::Object> copy;

        std::wstring wstrProvName(provName->begin(), provName->end());
        std::wstring wstrReaderName(readerName->begin(), readerName->end());
        std::wstring wstrScope = L"";
        wstrScope += L"\\\\.\\";
        wstrScope += wstrReaderName.c_str();
        wstrScope += L"\\";

        if (dynamic_cast<RsaPrivateKey*>(object.get())) {
            copy = Scoped<RsaPrivateKey>(new RsaPrivateKey(
                (LPWSTR)wstrProvName.c_str(),
                provType == SCARD_PROVIDER_KSP ? 0 : PROV_RSA_FULL,
                (LPWSTR)wstrScope.c_str()
            ));
        }
        else if (dynamic_cast<RsaPublicKey*>(object.get())) {
            copy = Scoped<RsaPublicKey>(new RsaPublicKey());
        }
        else if (dynamic_cast<EcPrivateKey*>(object.get())) {
            copy = Scoped<EcPrivateKey>(new EcPrivateKey(
                (LPWSTR)wstrProvName.c_str(),
                provType == SCARD_PROVIDER_KSP ? 0 : PROV_EC_ECDSA_FULL,
                (LPWSTR)wstrScope.c_str()
            ));
        }
        else if (dynamic_cast<EcPublicKey*>(object.get())) {
            copy = Scoped<EcPublicKey>(new EcPublicKey());
        }
        else if (dynamic_cast<EcPrivateKey*>(object.get())) {
            copy = Scoped<EcPrivateKey>(new EcPrivateKey());
        }
        else if (dynamic_cast<X509Certificate*>(object.get())) {
            copy = Scoped<X509Certificate>(new X509Certificate(
                (LPWSTR)wstrProvName.c_str(),
                provType,
                (LPWSTR)wstrScope.c_str()
            ));
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object is not copyable");
        }

        copy->CopyValues(object, pTemplate, ulCount);
        return copy;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::SmartCardSession::DestroyObject(CK_OBJECT_HANDLE hObject)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<core::Object> object = GetObject(hObject);

        X509Certificate* x509 = dynamic_cast<X509Certificate*>(object.get());
        if (x509) {
            DestroyCertificate(x509);
            objects.remove(object);

            return CKR_OK;
        }
        else {
            return core::Session::DestroyObject(hObject);
        }
    }
    CATCH_EXCEPTION
}

void mscapi::SmartCardSession::LoadProvider()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        switch (provType) {
        case SCARD_PROVIDER_CSP: {
            LoadProviderCSP();
            break;
        }
        case SCARD_PROVIDER_KSP: {
            LoadProviderKSP();
            break;
        }
        default:
            THROW_EXCEPTION("Unknown provider type in use");
        }
    }
    CATCH_EXCEPTION
}

void mscapi::SmartCardSession::LoadProviderCSP()
{
    THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
}

void mscapi::SmartCardSession::LoadProviderKSP()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        ncrypt::Provider provider;
        std::wstring wstrProvName(provName->begin(), provName->end());
        provider.Open(wstrProvName.c_str());

        // Get key names
        std::wstring wstrReader(readerName->begin(), readerName->end());
        std::wstring wstrScope = L"\\\\.\\" + wstrReader + L"\\";
        LOGGER_INFO("SCard: Getting objects from '%s' reader", readerName->c_str());
        auto keyNames = provider.GetKeyNames(wstrScope.c_str(), NCRYPT_SILENT_FLAG);

        for (int i = 0; i < keyNames->size(); i++) {
            auto keyName = keyNames->at(i);
            std::wstring wstrKeyName(keyName->pszName);
            std::string strKeyName(wstrKeyName.begin(), wstrKeyName.end());

            try {
                Scoped<crypt::ProviderInfo> provInfo(new crypt::ProviderInfo(keyName->pszName, wstrProvName.c_str(), 0, 0, keyName->dwLegacyKeySpec));
                Scoped<mscapi::CryptoKey> cryptoKey(new CryptoKey(provInfo));
                Scoped<ncrypt::Key> nKey(new ncrypt::Key);
                nKey->Open(wstrProvName.c_str(), keyName->pszName, keyName->dwLegacyKeySpec, NCRYPT_SILENT_FLAG);
                Scoped<core::Object> privateKey;
                Scoped<core::Object> publicKey;
                Scoped<mscapi::X509Certificate> x509;

                if (wcscmp(keyName->pszAlgid, NCRYPT_RSA_ALGORITHM) == 0) {
                    // RSA
                    auto rsaPrivateKey = Scoped<mscapi::RsaPrivateKey>(new mscapi::RsaPrivateKey);
                    rsaPrivateKey->SetKey(cryptoKey);
                    privateKey = rsaPrivateKey;

                    auto rsaPublicKey = Scoped<mscapi::RsaPublicKey>(new mscapi::RsaPublicKey);
                    rsaPublicKey->SetKey(nKey);
                    publicKey = rsaPublicKey;
                }
                else if (
                    wcscmp(keyName->pszAlgid, NCRYPT_ECDSA_ALGORITHM) == 0 ||
                    wcscmp(keyName->pszAlgid, NCRYPT_ECDH_ALGORITHM) == 0
                    ) {
                    // EC
                    auto ecPrivateKey = Scoped<mscapi::EcPrivateKey>(new mscapi::EcPrivateKey);
                    ecPrivateKey->SetKey(cryptoKey);
                    privateKey = ecPrivateKey;

                    auto ecPublicKey = Scoped<mscapi::EcPublicKey>(new mscapi::EcPublicKey);
                    ecPublicKey->SetKey(nKey);
                    publicKey = ecPublicKey;
                }
                else {
                    THROW_EXCEPTION("Unsupported key algorithm");
                }


                try {
                    auto certBlob = nKey->GetBytes(NCRYPT_CERTIFICATE_PROPERTY);
                    Scoped<crypt::Certificate> cert(new crypt::Certificate);
                    cert->Import(certBlob->data(), certBlob->size());

                    x509 = Scoped<mscapi::X509Certificate>(new mscapi::X509Certificate(
                        (LPWSTR)wstrProvName.c_str(),
                        provType,
                        (LPWSTR)wstrScope.c_str()
                    ));
                    x509->Assign(cert);
                }
                catch (Scoped<core::Exception>e) {
                    LOGGER_ERROR("Cannot load certificate for key '%s'. %s", strKeyName.c_str(), e->what());
                }

                auto id = nKey->GetID();
                privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                privateKey->ItemByType(CKA_ID)->SetValue(id->data(), id->size());
                publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                publicKey->ItemByType(CKA_ID)->SetValue(id->data(), id->size());
                if (x509.get()) {
                    x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                    objects.add(x509);
                }

                LOGGER_INFO("SCard: Private key '%s' was added", strKeyName.c_str());
                objects.add(privateKey);
                objects.add(publicKey);
            }
            catch (Scoped<core::Exception> e) {
                LOGGER_ERROR("Cannot load key '%s'. %s", strKeyName.c_str(), e->what());
                continue;
            }
        }
    }
    catch (Scoped<core::Exception> e) {
        LOGGER_ERROR("Cannot get objects from '%s'. %s", provName->c_str(), e->what());
    }
}

void mscapi::SmartCardSession::DestroyCertificate(mscapi::X509Certificate * x509)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        Scoped<Buffer> id = x509->Get()->GetID();
        auto key = GetPrivateKey(id.get());
        if (key.get() && key->IsCNG()) {
            ncrypt::Key* nkey = key->GetNKey();
            nkey->SetBytes(NCRYPT_CERTIFICATE_PROPERTY, NULL, 0);
        }
    }
    CATCH_EXCEPTION
}

Scoped<CryptoKey> mscapi::SmartCardSession::GetPrivateKey(Buffer * keyID)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        
        for (int i = 0; i < objects.count(); i++) {
            Scoped<core::Object> object = objects.items(i);
            mscapi::ObjectKey* key = dynamic_cast<ObjectKey*>(object.get());
            
            if (key && dynamic_cast<core::PrivateKey*>(object.get())) {
                Scoped<Buffer> id = key->GetKey()->GetID();

                if (memcmp(keyID->data(), id->data(), id->size()) == 0) {
                    return key->GetKey();
                }
            }
        }

        return NULL;
        
    }
    CATCH_EXCEPTION
}
