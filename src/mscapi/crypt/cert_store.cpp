#include "cert_store.h"
#include "../helper.h"

using namespace mscapi;
using namespace crypt;

void CertificateStorage::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    Close();
}

void CertificateStorage::Open(LPCSTR storeName)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        HCERTSTORE hStore = NULL;

        hStore = CertOpenSystemStoreA((HCRYPTPROV)NULL, storeName);
        if (!hStore) {
            THROW_MSCAPI_EXCEPTION("CertOpenSystemStoreA");
        }
        
        Set(hStore);
    }
    CATCH_EXCEPTION
}

void crypt::CertificateStorage::AddCertificate(
    Scoped<Certificate> cert,
    ULONG               dwFlags
)
{
    try {
        PCCERT_CONTEXT storeCert;
        if (!CertAddCertificateContextToStore(
            Get(),
            cert->Get(),
            dwFlags,
            &storeCert
        )) {
            THROW_MSCAPI_EXCEPTION("CertAddCertificateContextToStore");
        }

        cert->Set(storeCert);
    }
    CATCH_EXCEPTION
}

void crypt::CertificateStorage::Close()
{
    try {
        if (!IsEmpty()) {
            if (!CertCloseStore(Get(), 0)) {
                THROW_MSCAPI_EXCEPTION("CertCloseStore");
            }
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION;
}

Scoped<CertificateList> crypt::CertificateStorage::GetCertificates()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<CertificateList> certs(new CertificateList(0));

        // get certificates
        PCCERT_CONTEXT hCert = NULL;
        while (true)
        {
            hCert = CertEnumCertificatesInStore(Get(),hCert);
            
            if (!hCert) {
                break;
            }
            else {
                PCCERT_CONTEXT hCopy = CertDuplicateCertificateContext(hCert);
                Scoped<Certificate> cert(new Certificate());
                cert->Set(hCopy);
                certs->push_back(cert);
            }
        }

        LOGGER_DEBUG("%s %d items", __FUNCTION__, certs->size());

        return certs;
    }
    CATCH_EXCEPTION
}