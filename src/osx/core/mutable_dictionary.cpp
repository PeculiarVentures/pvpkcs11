#include "mutable_dictionary.h"

using namespace osx;

Scoped<CFMutableDictionary> CFMutableDictionary::CreateMutable(CFAllocatorRef allocator, CFIndex capacity, CFDictionaryRef dict)
{ 
  FUNCTION_BEGIN

  CFMutableDictionaryRef res = CFDictionaryCreateMutableCopy(allocator, capacity, dict);
  if (res == nullptr) {
    THROW_EXCEPTION("Error on CFDictionaryCreateMutableCopy");
  }

  return Scoped<CFMutableDictionary>(new CFMutableDictionary(res));

  FUNCTION_END
}

Scoped<CFMutableDictionary> CFMutableDictionary::Create(CFAllocatorRef allocator, CFIndex capacity, const CFDictionaryKeyCallBacks *keyCallBacks, const CFDictionaryValueCallBacks *valueCallBacks)
{
  FUNCTION_BEGIN

  CFMutableDictionaryRef dict = CFDictionaryCreateMutable(allocator, capacity, keyCallBacks, valueCallBacks);

  return Scoped<CFMutableDictionary>(new CFMutableDictionary(dict));

  FUNCTION_END
}

CFMutableDictionary *CFMutableDictionary::AddValue(const void *key, const void *value)
{
  FUNCTION_BEGIN

  CFDictionaryAddValue((CFMutableDictionaryRef)handle, key, value);

  return this;

  FUNCTION_END
}

CFMutableDictionary *CFMutableDictionary::SetValue(const void *key, const void *value)
{
  FUNCTION_BEGIN

  CFDictionarySetValue((CFMutableDictionaryRef)handle, key, value);
  
  return this;

  FUNCTION_END
}
