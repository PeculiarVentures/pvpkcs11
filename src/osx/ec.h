#pragma once

#include "../stdafx.h"

#include "../core/keypair.h"
#include "../core/objects/ec_key.h"
#include "key.h"

namespace osx {
    
    class EcKey {
    public:
        static Scoped<core::KeyPair> Generate
        (
         CK_MECHANISM_PTR       pMechanism,
         Scoped<core::Template> publicTemplate,
         Scoped<core::Template> privateTemplate
         );
        
        static Scoped<core::Object> DeriveKey
        (
         CK_MECHANISM_PTR        pMechanism,
         Scoped<core::Object>    baseKey,
         Scoped<core::Template>  tmpl
         );
    };
    
    class EcPrivateKey : public core::EcPrivateKey, public Key {
    public:
        void Assign(SecKeyRef key);
        
        CK_RV CopyValues
        (
         Scoped<core::Object>    object,     /* the object which must be copied */
         CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
         CK_ULONG                ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
    protected:
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();
        
        CK_RV GetValue
        (
         CK_ATTRIBUTE_PTR attr
         );
    };
    
    class EcPublicKey : public core::EcPublicKey, public Key {
    public:
        void Assign(SecKeyRef key);
        
        CK_RV CreateValues
        (
         CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
         CK_ULONG          ulCount     /* attributes in template */
        );
        
        CK_RV CopyValues
        (
         Scoped<core::Object>    object,     /* the object which must be copied */
         CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
         CK_ULONG                ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
    protected:
        void FillKeyStruct();
        
        CK_RV GetValue
        (
         CK_ATTRIBUTE_PTR  attr
         );
    };
    
}
