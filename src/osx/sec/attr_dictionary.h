#pragma once

#include <Security/SecItem.h>

#include "../core.h"

namespace osx
{

  class SecAttributeDictionary : public CFDictionary
  {
  public:
    SecAttributeDictionary() : CFDictionary() {}
    SecAttributeDictionary(CFTypeRef handle) : CFDictionary(handle) {}

    Scoped<CFType> GetValueRef();

    Scoped<CFString> GetClass();
    Scoped<CFString> GetLabel();
    Scoped<CFData> GetPublicKeyHash();
    Scoped<CFData> GetSubjectKeyId();
    Scoped<CFData> GetIssuer();
    Scoped<CFData> GetSerialNumber();
  };

}
