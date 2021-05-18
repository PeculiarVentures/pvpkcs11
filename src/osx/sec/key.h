#pragma once

#include "../core.h"

#include <Security/SecKey.h>

namespace osx
{

  class SecKey : public CFRef<SecKeyRef>
  {
  public:
    SecKey() : CFRef<SecKeyRef>() {}
    SecKey(_Nonnull SecKeyRef handle) : CFRef<SecKeyRef>(handle) {}

    static void GeneratePair(_Nonnull CFDictionaryRef parameters, SecKeyRef * _Nullable CF_RETURNS_RETAINED publicKey, SecKeyRef * _Nullable CF_RETURNS_RETAINED privateKey);
    static Scoped<SecKey> Generate(
        SecKeychainRef _Nullable keychainRef,
        CSSM_ALGORITHMS algorithm,
        uint32 keySizeInBits,
        CSSM_CC_HANDLE contextHandle,
        CSSM_KEYUSE keyUsage,
        uint32 keyAttr,
        SecAccessRef _Nullable initialAccess);
    static Scoped<SecKey> CreateFromData(_Nonnull CFDictionaryRef parameters, _Nonnull CFDataRef keyData);
    Scoped<CFDictionary> GetAttributes();
    Scoped<CFData> GetExternalRepresentation();
    Scoped<CFData> GetKeyExchangeResult(_Nonnull SecKeyAlgorithm algorithm, _Nonnull SecKeyRef publicKey, _Nonnull CFDictionaryRef parameters);
    Scoped<CFData> CreateSignature(_Nonnull SecKeyAlgorithm algorithm, _Nonnull CFDataRef dataToSign);
    Boolean VerifySignature(_Nonnull SecKeyAlgorithm algorithm, _Nonnull CFDataRef signedData, _Nonnull CFDataRef signature);
  };

}