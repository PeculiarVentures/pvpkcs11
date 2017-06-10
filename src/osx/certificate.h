#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"

#include <Security.h>

namespace osx {

    class X509Certificate : public core::X509Certificate {
    public:
        X509Certificate(): value(NULL){}
        
        void Assign(
            SecCertificateRef        cert
        );
        SecCertificateRef Get();

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

    protected:
        SecCertificateRef value;
        
        void AddToMyStorage();
    };


}
