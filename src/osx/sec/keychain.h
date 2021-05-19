#pragma once

#include <Security/SecKeychain.h>
#include <Security/SecItem.h>

#include "../core.h"

namespace osx
{

  class SecKeychain : public CFRef<SecKeychainRef>
  {
    public:
      SecKeychain() : CFRef<SecKeychainRef>() {}
      SecKeychain(CFTypeRef handle) : CFRef<SecKeychainRef>(handle) {}

      static Scoped<SecKeychain> CreateEmpty();
      static Scoped<SecKeychain> GetDefault();
      static Scoped<SecKeychain> Open(const char * path);

      Scoped<CFArray> GetItems(CFStringRef matchType);

      Scoped<CFArray> GetCertificates();
      Scoped<CFArray> GetIdentities();
      Scoped<CFArray> GetKeys();
  };

}