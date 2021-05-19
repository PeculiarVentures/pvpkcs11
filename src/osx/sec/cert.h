#pragma once

#include <Security/SecCertificate.h>

#include "../core.h"
#include "key.h"

namespace osx
{

  class SecCertificate : public CFRef<SecCertificateRef>
  {
  public:
    SecCertificate() : CFRef<SecCertificateRef>() {}
    SecCertificate(_Nonnull CFTypeRef handle) : CFRef<SecCertificateRef>(handle) {}

    static Scoped<SecCertificate> CreateWithData(CFAllocatorRef _Nullable allocator, CFDataRef _Nonnull data);
    static Scoped<SecCertificate> CreateRetain(SecCertificateRef _Nonnull cert);

    Scoped<CFString> GetCommonName();
    Scoped<CFData> GetData();
    Scoped<CFData> GetNormalizedIssuerSequence();
    Scoped<CFData> GetNormalizedSubjectSequence();
    Scoped<CFData> GetSerialNumberData();
    void AddToKeychain(SecKeychainRef _Nullable keyChain);
    Scoped<SecKey> GetPublicKey();
    Scoped<CFString> GetSubjectSummary();
    Scoped<CFDictionary> GetValues(CFArrayRef _Nullable keys = NULL);
  };

}