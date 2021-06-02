#pragma once

#include "../stdafx.h"

#include "../core/keypair.h"
#include "../core/objects/rsa_private_key.h"
#include "../core/objects/rsa_public_key.h"
#include "key.h"
#include "sec.h"

namespace osx
{

  class RsaKey
  {
  public:
    static Scoped<core::KeyPair> Generate(
        CK_MECHANISM_PTR pMechanism,
        Scoped<core::Template> publicTemplate,
        Scoped<core::Template> privateTemplate);
  };

  class RsaPrivateKey : public core::RsaPrivateKey, public Key
  {
  public:
    /**
     * Assigns private key
     * 
     * @remarks Method uses SecKeyCopyAttributes which shows dialog if key has not permission for runned application
     * 
     * @param key Private key ref
     */
    void Assign(Scoped<SecKey> key);
    /**
     * Assign private key from attribute dictionary
     * 
     * @param attrs Attribute dictionary
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

    CK_RV GetValue(
        CK_ATTRIBUTE_PTR attr);
  };

  class RsaPublicKey : public core::RsaPublicKey, public Key
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
