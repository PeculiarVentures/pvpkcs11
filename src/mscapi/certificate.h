#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
#include "crypt/crypt.h"

namespace mscapi {

    class X509Certificate : public core::X509Certificate {
    public:
        X509Certificate();

        void Assign(
            Scoped<crypt::Certificate>     cert
        );
        Scoped<crypt::Certificate> Get();

        Scoped<Buffer> GetPublicKeyHash(
            CK_MECHANISM_TYPE       mechType
        );

        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV CopyValues(
            Scoped<Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV Destroy();

        Scoped<core::Object> GetPublicKey();
        Scoped<core::Object> GetPrivateKey();

    protected:
        Scoped<crypt::Certificate> value;
        Scoped<core::Object> publicKey;
        Scoped<core::Object> privateKey;
        
        void AddToMyStorage();
        CK_RV GetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );
    };


}