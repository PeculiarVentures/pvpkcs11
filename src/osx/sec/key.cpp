#include "key.h"

using namespace osx;

Scoped<SecKey> SecKey::CreateFromData(CFDictionaryRef parameters, CFDataRef keyData)
{
  CFError error;
  SecKeyRef key = SecKeyCreateFromData(parameters, keyData, &error);
  if (!error.IsEmpty())
  {
    Scoped<CFString> errorText = error.GetDescription();
    THROW_EXCEPTION(errorText->GetCStringPtr());
  }
}

Scoped<CFDictionary> SecKey::GetAttributes()
{
  CFDictionaryRef dict = SecKeyCopyAttributes(handle);
  if (!dict)
  {
    THROW_EXCEPTION("Error on SecKeyCopyAttributes");
  }

  return Scoped<CFDictionary>(new CFDictionary(dict));
}

Scoped<CFData> SecKey::GetExternalRepresentation()
{
  CFError error = CFError();

  CFDataRef data = SecKeyCopyExternalRepresentation(handle, &error);
  if (!data)
  {
    THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
  }

  return Scoped<CFData>(new CFData(data));
}

void SecKey::GeneratePair(CFDictionaryRef parameters, SecKeyRef *publicKey, SecKeyRef *privateKey)
{
  OSStatus status = SecKeyGeneratePair(parameters, publicKey, privateKey);
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecKeyGeneratePair");
  }
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
}

Scoped<CFData> SecKey::GetKeyExchangeResult(SecKeyAlgorithm algorithm, SecKeyRef publicKey, CFDictionaryRef parameters)
{
  CFError error;
  CFDataRef data = SecKeyCopyKeyExchangeResult(handle, algorithm, publicKey, parameters, &error);
  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCStringPtr());
  }

  return Scoped<CFData>(new CFData(data));
}

Scoped<CFData> SecKey::CreateSignature(SecKeyAlgorithm algorithm, CFDataRef dataToSign)
{
  CFError error;

  CFDataRef data = SecKeyCreateSignature(handle, algorithm, dataToSign, &error);

  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCStringPtr());
  }

  return Scoped<CFData>(new CFData(data));
}

Boolean SecKey::VerifySignature(SecKeyAlgorithm algorithm, CFDataRef signedData, CFDataRef signature)
{
  CFError error;

  Boolean res = SecKeyVerifySignature(handle, algorithm, signedData, signature, &error);

  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCStringPtr());
  }

  return res;
}
