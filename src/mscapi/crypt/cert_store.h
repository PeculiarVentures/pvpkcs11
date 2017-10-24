#pragma once

#include "../../stdafx.h"
#include "../handle.h"
#include "cert.h"

namespace crypt {

#define PV_STORE_NAME_MY            "MY"
#define PV_STORE_NAME_REQUEST       "REQUEST"

    using CertificateList = SList<Certificate>;

    class CertificateStorage : public mscapi::Handle<HCERTSTORE> {
    public:
        CertificateStorage() : Handle() {}
        CertificateStorage(HCERTSTORE handle) : Handle(handle) {}

        void Dispose();

        void Open(LPCSTR storeName);
        void Close();

        Scoped<CertificateList> CertificateStorage::GetCertificates();
        void AddCertificate(
            Scoped<Certificate> cert,
            ULONG               dwFlags = 0
        );
    };
    
}