#include "mutable_dictionary.h"

using namespace osx;

Scoped<CFMutableDictionary> CFMutableDictionary::CreateMutable(CFAllocatorRef allocator, CFIndex capacity, CFDictionaryRef dict)
{ 
  CFMutableDictionaryRef res = CFDictionaryCreateMutableCopy(allocator, capacity, dict);
  if (res == nullptr) {
    THROW_EXCEPTION("Error on CFDictionaryCreateMutableCopy");
  }

  return Scoped<CFMutableDictionary>(new CFMutableDictionary(res));
}

Scoped<CFMutableDictionary> CFMutableDictionary::Create(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks)
{
  CFMutableDictionaryRef dict = CFDictionaryCreateMutable(allocator, capacity, keyCallBacks, valueCallBacks);

  return Scoped<CFMutableDictionary>(new CFMutableDictionary(dict));
}

CFMutableDictionary *CFMutableDictionary::AddValue(const void *key, const void *value)
{
  CFDictionaryAddValue((CFMutableDictionaryRef)handle, key, value);

  return this;
}

CFMutableDictionary *CFMutableDictionary::SetValue(const void *key, const void *value)
{
  CFDictionarySetValue((CFMutableDictionaryRef)handle, key, value);
  
  return this;
}
