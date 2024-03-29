#pragma once

#include <Security/SecIdentity.h>

#include "../core.h"
#include "cert.h"
#include "key.h"

namespace osx
{

  class SecIdentity : public CFRef<SecIdentityRef>
  {
  public:
    static Scoped<SecIdentity> CreateWithCertificate(CFTypeRef __nullable keychainOrArray, SecCertificateRef cert);

    SecIdentity() : CFRef<SecIdentityRef>() {}
    SecIdentity(_Nonnull CFTypeRef handle) : CFRef<SecIdentityRef>(handle) {}

    Scoped<SecCertificate> GetCertificate();
    Scoped<SecKey> GetPrivateKey();
  };

}
