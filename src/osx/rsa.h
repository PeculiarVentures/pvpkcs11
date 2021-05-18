#pragma once

#include "../stdafx.h"

#include "../core/keypair.h"
#include "../core/objects/rsa_private_key.h"
#include "../core/objects/rsa_public_key.h"
#include "helper.h"
#include "key.h"

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
    
    class RsaPrivateKey : public core::RsaPrivateKey, public Key {
    public:
        
        /**
         Assign private key

         @param key Private key ref
         
         NOTE: method uses SecKeyCopyAttributes which shows dilog if key has not permission for runned application
         */
        void Assign(Scoped<SecKey> key);
        /**
         Assign private key and use public key to fill public data

         @param key Private key ref
         @param publicKey Public key linked to private key
         */
        void Assign(Scoped<SecKey> key, Scoped<core::PublicKey> publicKey);
        
        CK_RV CopyValues(
                         Scoped<core::Object>    object,     /* the object which must be copied */
                         CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
                         CK_ULONG                ulCount     /* attributes in template */
        );
        
        CK_RV Destroy();
        
    protected:
        void FillPublicKeyStruct();
        void FillPrivateKeyStruct();
        
        CK_RV GetValue(
                       CK_ATTRIBUTE_PTR attr
                       );
    };
    
    class RsaPublicKey : public core::RsaPublicKey, public Key {
    public:
        void Assign(Scoped<SecKey> key);
        
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
