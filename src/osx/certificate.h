#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
#include "../core/objects/public_key.h"
#include "../core/objects/private_key.h"

#include <Security.h>
#include "helper.h"

namespace osx {
    
    class X509Certificate : public core::X509Certificate {
    public:
        X509Certificate();
        
        void Assign
        (
         SecCertificateRef        cert      /* OSX certificate reference */
        );
        void Assign
        (
         SecCertificateRef        cert,     /* OSX certificate reference */
         CK_BBOOL                 free      /* destroy ref in destructor */
        );
        SecCertificateRef Get();
        
        Scoped<Buffer> GetPublicKeyHash();
        
        CK_RV CreateValues
        (
         CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
         CK_ULONG          ulCount     /* attributes in template */
        );
        
        CK_RV CopyValues
        (
         Scoped<Object>    object,     /* the object which must be copied */
         CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
         CK_ULONG          ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
        Scoped<core::PublicKey> GetPublicKey();
        Scoped<core::PrivateKey> GetPrivateKey();
        bool HasPrivateKey();
        Scoped<X509Certificate> Copy();
        
    protected:
        CFRef<SecCertificateRef> value;
        
        void AddToMyStorage();
        
        CK_RV GetValue
        (
         CK_ATTRIBUTE_PTR  attr         /* attribute */
        );
    };
    
    
}
