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
    SecIdentity() : CFRef<SecIdentityRef>() {}
    SecIdentity(_Nonnull SecIdentityRef handle) : CFRef<SecIdentityRef>(handle) {}

    Scoped<SecCertificate> GetCertificate();
    Scoped<SecKey> GetPrivateKey();
  };

}
