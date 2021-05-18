#pragma once

#include <Security/SecItem.h>

#include "../core.h"

namespace osx
{

  class SecAttributeDictionary : public CFDictionary
  {
  public:
    SecAttributeDictionary() : CFDictionary() {}
    SecAttributeDictionary(CFDictionaryRef handle) : CFDictionary(handle) {}

    CFTypeRef GetValueRef();
    CFTypeRef CopyValueRef();
    template <typename T>
    T CopyValueRef()
    {
      return (T)(CopyValueRef());
    }

    Scoped<CFString> GetClass();
    Scoped<CFString> GetLabel();
    Scoped<CFData> GetPublicKeyHash();
    Scoped<CFData> GetSubjectKeyId();
    Scoped<CFData> GetIssuer();
    Scoped<CFData> GetSerialNumber();
  };

}
