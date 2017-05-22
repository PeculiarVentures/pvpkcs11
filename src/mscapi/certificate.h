#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
#include "crypt/crypt.h"

namespace mscapi {

    class X509Certificate : public core::X509Certificate {
    public:
        void Assign(
            Scoped<crypt::Certificate>     cert
        );
        Scoped<crypt::Certificate> Get();

        Scoped<Buffer> GetPublicKeyHash(
            CK_MECHANISM_TYPE       mechType
        );
    protected:
        Scoped<crypt::Certificate> value;
    };


}