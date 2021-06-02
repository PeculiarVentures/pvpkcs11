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
    CFDictionary(CFTypeRef _Nonnull handle) : CFRef<CFDictionaryRef>(handle) {}

    static Scoped<CFDictionary> Create(CFAllocatorRef _Nullable allocator, CFDictionaryRef _Nonnull dict);

    bool HasValue(const void *key);
    Scoped<CFType> GetValue(const void *key);
    Scoped<CFType> GetValueOrNull(const void *key);
    Boolean GetValueIfPresent(const void *key, const void **value);

  protected:
    const void *_Nullable GetValueByKey(const void *_Nonnull key);
  };

}