#pragma once

#include <Security/SecKeychain.h>
#include <Security/SecItem.h>

#include "../core.h"

namespace osx
{

  class SecKeychain : public CFRef<SecKeychainRef>
  {
    public:
      static Scoped<SecKeychain> CreateEmpty();
      static Scoped<SecKeychain> GetDefault();

      Scoped<CFArray> GetItems(CFStringRef matchType);

      Scoped<CFArray> GetCertificates();
      Scoped<CFArray> GetIdentities();
      Scoped<CFArray> GetKeys();
  };

}