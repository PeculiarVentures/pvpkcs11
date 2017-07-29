#include "crypt.h"

using namespace crypt;

CertStore::CertStore()
{
    try {
        this->hStore = NULL;
    }
    CATCH_EXCEPTION;
}

CertStore::~CertStore()
{
    try {
        this->Close();
    }
    catch (...) {
    }
}

void CertStore::Open(LPCSTR storeName)
{
    try {
        this->hStore = CertOpenSystemStoreA((HCRYPTPROV)NULL, storeName);
        if (this->hStore == NULL_PTR) {
            THROW_MSCAPI_EXCEPTION();
        }
        this->name = storeName;
        this->opened = true;
    }
    CATCH_EXCEPTION;
}

void CertStore::AddCertificate(
    Scoped<Certificate> cert,
    ULONG               dwFlags
)
{
    try {
        PCCERT_CONTEXT storeCert;
        if (!CertAddCertificateContextToStore(
            hStore,
            cert->Get(),
            dwFlags,
            &storeCert
        )) {
            THROW_MSCAPI_EXCEPTION();
        }

        cert->Assign(storeCert);
    }
    CATCH_EXCEPTION
}

void CertStore::Close()
{
    try {
        if (this->hStore) {
            CertCloseStore(this->hStore, 0);
            this->hStore = NULL;
        }
    }
    CATCH_EXCEPTION;
}

std::vector<Scoped<Certificate> > CertStore::GetCertificates()
{
    std::vector<Scoped<Certificate> > certs;
    // get certificates
    PCCERT_CONTEXT hCert = NULL;
    while (true)
    {
        hCert = CertEnumCertificatesInStore(
            this->hStore,
            hCert
        );
        if (hCert == NULL) {
            break;
        }
        else {
            PCCERT_CONTEXT hCopy = CertDuplicateCertificateContext(hCert);
            Scoped<Certificate> cert(new Certificate());
            cert->Assign(hCopy);
            certs.push_back(cert);
        }
    }
    return certs;
}