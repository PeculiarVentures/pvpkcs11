#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
// #include "crypt/crypt.h"

namespace mscapi {

    class X509Certificate : public core::X509Certificate {
    public:
        ~X509Certificate();

        void Assign(
            PCCERT_CONTEXT context
        );

        Scoped<Buffer> GetPublicKeyHash(
            CK_MECHANISM_PTR             pMechanism
        );

        void Destroy();
    protected:
        PCCERT_CONTEXT context;
    };


}