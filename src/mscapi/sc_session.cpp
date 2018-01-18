#include "sc_session.h"
#include "certificate.h"

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
                auto info = cert->GetProviderInfo();
                if (info->IsAccassible()) {
                    auto scName = info->GetSmartCardReader();
                    if (scName->compare(readerName->c_str()) == 0) {

#pragma region Add objects
                        Scoped<X509Certificate> x509(new X509Certificate());
                        x509->Assign(cert);

                        x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                        x509->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(false);
                        x509->ItemByType(CKA_MODIFIABLE)->To<core::AttributeBool>()->Set(false);

                        Scoped<core::Object> publicKey = x509->GetPublicKey();
                        Scoped<core::Object> privateKey = x509->GetPrivateKey();

                        if (privateKey.get() && publicKey.get()) {
                            privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                            publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
                            objects.add(privateKey);
                            objects.add(publicKey);
                            objects.add(x509);
                        }
#pragma endregion
                    }
                }
            }
            catch (Scoped<core::Exception> e) {
                // skip cert
                LOGGER_INFO("Skip certificate %s", certName->c_str());
                LOGGER_ERROR("%s", e->what());
            }
        }

        return res;
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
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> mscapi::SmartCardSession::CopyObject(Scoped<core::Object> object, CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
