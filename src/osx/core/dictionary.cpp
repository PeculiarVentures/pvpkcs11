#include "dictionary.h"

using namespace osx;

Scoped<CFDictionary> CFDictionary::Create(CFAllocatorRef allocator, CFDictionaryRef dict)
{
  CFDictionaryRef res = CFDictionaryCreateCopy(allocator, dict);
  if (res == nullptr) {
    THROW_EXCEPTION("Error on CFDictionaryCreateCopy");
  }

  return Scoped<CFDictionary>(new CFDictionary(res));
}

const void *CFDictionary::GetValue(const void *key)
{
  return CFDictionaryGetValue(handle, key);
}

CFTypeRef  CFDictionary::CopyValue(const void *key)
{
  CFTypeRef ref = reinterpret_cast<CFTypeRef>(GetValue(key));

  return CFRetain(ref);
}

Boolean CFDictionary::GetValueIfPresent(const void *key, const void **value)
{
  return CFDictionaryGetValueIfPresent(handle, key, value);
}

Scoped<CFData> CFDictionary::GetValueCFData(const void *key)
{
  CFDataRef ref = CopyValue<CFDataRef>(key);

  return Scoped<CFData>(new CFData(ref));
}

Scoped<CFString> CFDictionary::GetValueCFString(const void *key)
{
  CFStringRef ref = CopyValue<CFStringRef>(key);

  return Scoped<CFString>(new CFString(ref));
}
