#pragma once

#include "../stdafx.h"

#include "../core/keypair.h"
#include "../core/objects/ec_key.h"
#include "key.h"
#include "sec.h"

namespace osx
{

  class EcKey
  {
  public:
    static Scoped<core::KeyPair> Generate(
        CK_MECHANISM_PTR pMechanism,
        Scoped<core::Template> publicTemplate,
        Scoped<core::Template> privateTemplate);

    static Scoped<core::Object> DeriveKey(
        CK_MECHANISM_PTR pMechanism,
        Scoped<core::Object> baseKey,
        Scoped<core::Template> tmpl);
  };

  class EcPrivateKey : public core::EcPrivateKey, public Key
  {
  public:
    /**
         Assign private key
         
         @param key Private key ref
         
         NOTE: method uses SecKeyCopyAttributes which shows dialog if key has not permission for runned application
         */
    void Assign(Scoped<SecKey> key);
    /**
         Assign private key and use public key to fill public data
         
         @param key Private key ref
         @param publicKey Public key linked to private key
         */
    void Assign(Scoped<SecKey>, Scoped<core::PublicKey> publicKey);
    /**
         * Assign private key from Keychain attributes
         */
    void Assign(SecAttributeDictionary *attrs);

    CK_RV CopyValues(
        Scoped<core::Object> object, /* the object which must be copied */
        CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
        CK_ULONG ulCount             /* attributes in template */
    );

    CK_RV Destroy();

  protected:
    void FillPublicKeyStruct();
    void FillPrivateKeyStruct();
    void SetECParams(CK_ULONG keySizeInBits);

    CK_RV GetValue(
        CK_ATTRIBUTE_PTR attr);
  };

  class EcPublicKey : public core::EcPublicKey, public Key
  {
  public:
    void Assign(Scoped<SecKey> key);

    CK_RV CreateValues(
        CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
        CK_ULONG ulCount            /* attributes in template */
    );

    CK_RV CopyValues(
        Scoped<core::Object> object, /* the object which must be copied */
        CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
        CK_ULONG ulCount             /* attributes in template */
    );

    CK_RV Destroy();

  protected:
    void FillKeyStruct();

    CK_RV GetValue(
        CK_ATTRIBUTE_PTR attr);
  };

}
