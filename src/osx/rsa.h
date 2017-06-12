#pragma once

#include "../stdafx.h"

#include "../core/keypair.h"
#include "../core/objects/rsa_private_key.h"
#include "../core/objects/rsa_public_key.h"

#include <Security/Security.h>

namespace osx {
    
    class RsaKey {
    public:
        static Scoped<core::KeyPair> Generate(
            CK_MECHANISM_PTR       pMechanism,
            Scoped<core::Template> publicTemplate,
            Scoped<core::Template> privateTemplate
        );
    };
    
    class RsaPrivateKey : public core::RsaPrivateKey {
    public:
        RsaPrivateKey() :
        core::RsaPrivateKey()
        {};
        
        CK_RV CopyValues(
                         Scoped<core::Object>    object,     /* the object which must be copied */
                         CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
                         CK_ULONG                ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
        void OnKeyAssigned();
        
    protected:
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();
        
        CK_RV GetValue(
                       CK_ATTRIBUTE_PTR attr
                       );
    };
    
    class RsaPublicKey : public core::RsaPublicKey {
    public:
        RsaPublicKey() :
        core::RsaPublicKey()
        {};
        
        void Dispose();
        
        void Assign(SecKeyRef key);
        
        CK_RV CreateValues(
                           CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
                           CK_ULONG          ulCount     /* attributes in template */
        );
        
        CK_RV CopyValues(
                         Scoped<core::Object>    object,     /* the object which must be copied */
                         CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
                         CK_ULONG                ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
    protected:
        SecKeyRef value;
        
        void FillKeyStruct();
        
        CK_RV GetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );
    };
    
}
