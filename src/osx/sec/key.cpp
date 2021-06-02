#include "key.h"
#include "cert.h"
#include "keychain.h"
#include "identity.h"

using namespace osx;

Scoped<SecKey> SecKey::CreateFromData(CFDictionaryRef parameters, CFDataRef keyData)
{
  FUNCTION_BEGIN

  CFError error;
  SecKeyRef key = SecKeyCreateFromData(parameters, keyData, &error);

  if (!error.IsEmpty())
  {
    Scoped<CFString> errorText = error.GetDescription();
    THROW_EXCEPTION(errorText->GetCString()->c_str());
  }

  return Scoped<SecKey>(new SecKey(key));

  FUNCTION_END
}

Scoped<CFDictionary> SecKey::GetAttributes()
{
  FUNCTION_BEGIN

  CFDictionaryRef dict = SecKeyCopyAttributes(handle);
  if (!dict)
  {
    THROW_EXCEPTION("Error on SecKeyCopyAttributes");
  }

  return Scoped<CFDictionary>(new CFDictionary(dict));

  FUNCTION_END
}

Scoped<CFData> SecKey::GetExternalRepresentation()
{
  FUNCTION_BEGIN

  CFError error;

  CFDataRef data = SecKeyCopyExternalRepresentation(handle, &error);
  if (!error.IsEmpty())
  {
    THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation. %s", error.GetDescription()->GetCString()->c_str());
  }

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

void SecKey::GeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey)
{
  FUNCTION_BEGIN

  OSStatus status = SecKeyGeneratePair(parameters, publicKey, privateKey);
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecKeyGeneratePair");
  }

  FUNCTION_END
}

Scoped<SecKey> SecKey::Generate(
    SecKeychainRef _Nullable keychainRef,
    CSSM_ALGORITHMS algorithm,
    uint32 keySizeInBits,
    CSSM_CC_HANDLE contextHandle,
    CSSM_KEYUSE keyUsage,
    uint32 keyAttr,
    SecAccessRef _Nullable initialAccess)
{
  FUNCTION_BEGIN

  Scoped<SecKey> key = Scoped<SecKey>(new SecKey);

  OSStatus status = SecKeyGenerate(
      keychainRef,
      algorithm,
      keySizeInBits,
      contextHandle,
      keyUsage,
      keyAttr,
      initialAccess,
      key->Ref());
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecKeyGenerate");
  }

  return key;

  FUNCTION_END
}

Scoped<CFData> SecKey::GetKeyExchangeResult(SecKeyAlgorithm algorithm, SecKeyRef publicKey, CFDictionaryRef parameters)
{
  FUNCTION_BEGIN

  CFError error;
  CFDataRef data = SecKeyCopyKeyExchangeResult(handle, algorithm, publicKey, parameters, &error);
  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCString()->c_str());
  }

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Scoped<CFData> SecKey::CreateSignature(SecKeyAlgorithm algorithm, CFDataRef dataToSign)
{
  FUNCTION_BEGIN

  CFError error;

  CFDataRef data = SecKeyCreateSignature(handle, algorithm, dataToSign, &error);

  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCString()->c_str());
  }

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Boolean SecKey::VerifySignature(SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature)
{
  FUNCTION_BEGIN

  CFError error;

  Boolean res = SecKeyVerifySignature(handle, algorithm, signedData, signature, &error);

  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCString()->c_str());
  }

  return res;

  FUNCTION_END
}

Scoped<SecKey> SecKey::GetPublicKey()
{
  FUNCTION_BEGIN

  OSStatus status = errSecSuccess;

  // Tries to get public key from certificate by kSecAttrSubjectKeyID
  {
    Scoped<SecKeychain> keychain = SecKeychain::GetDefault();
    Scoped<CFArray> identities = keychain->GetIdentities();

    for (CFIndex i = 0; i < identities->GetCount(); i++)
    {
      Scoped<CFDictionary> item = identities->GetValue(i)->To<CFDictionary>();

      Scoped<SecIdentity> identity = item->GetValue(kSecValueRef)->To<SecIdentity>();

      if (identity->GetPrivateKey()->IsEqual(handle))
      {
        return identity->GetCertificate()->GetPublicKey();
      }
    }
  }

  // Uses standard SecKeyCopyPublicKey function
  SecKey res = SecKeyCopyPublicKey(handle);

  if (res.IsEmpty())
  {
    THROW_EXCEPTION("Error on SecKeyCopyPublicKey");
  }

  return res.To<SecKey>();

  FUNCTION_END
}