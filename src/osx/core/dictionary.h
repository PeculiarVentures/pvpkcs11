#pragma once

#include "ref.h"
#include "string.h"
#include "data.h"

namespace osx
{

  class CFDictionary : public CFRef<CFDictionaryRef>
  {
  public:
    CFDictionary() : CFRef<CFDictionaryRef>() {}
    CFDictionary(CFDictionaryRef _Nonnull handle) : CFRef<CFDictionaryRef>(handle) {}

    static Scoped<CFDictionary> Create(CFAllocatorRef _Nullable allocator, CFDictionaryRef _Nonnull dict);

    const void * _Nonnull GetValue(const void * _Nonnull key);
    template <typename T>
    T _Nonnull GetValue(const void * _Nonnull key)
    {
      return (T)(GetValue(key));
    }
    CFTypeRef _Nonnull CopyValue(const void * _Nonnull key);
    template <typename T>
    T CopyValue(const void * _Nonnull key)
    {
      return (T)(CopyValue(key));
    }
    Boolean GetValueIfPresent(const void *key, const void ** value);

    Scoped<CFData> GetValueCFData(const void * _Nonnull key);
    Scoped<CFString> GetValueCFString(const void * _Nonnull key);
  };

}