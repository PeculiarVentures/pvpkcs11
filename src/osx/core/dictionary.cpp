#include "dictionary.h"

using namespace osx;

Scoped<CFDictionary> CFDictionary::Create(CFAllocatorRef allocator, CFDictionaryRef dict)
{
  CFDictionaryRef res = CFDictionaryCreateCopy(allocator, dict);
  if (res == nullptr)
  {
    THROW_EXCEPTION("Error on CFDictionaryCreateCopy");
  }

  return Scoped<CFDictionary>(new CFDictionary(res));
}

const void *CFDictionary::GetValueByKey(const void *key)
{
  return CFDictionaryGetValue(handle, key);
}

CFTypeRef CFDictionary::CopyValueByKey(const void *key)
{
  CFTypeRef ref = reinterpret_cast<CFTypeRef>(GetValueByKey(key));

  return CFRetain(ref);
}

Boolean CFDictionary::GetValueIfPresent(const void *key, const void **value)
{
  return CFDictionaryGetValueIfPresent(handle, key, value);
}

Scoped<CFType> CFDictionary::GetValue(const void *key)
{
  Scoped<CFType> item = GetValueOrNull(key);

  if (item->IsEmpty()) {
    CFTypeID typeID = CFGetTypeID(key);
    if (typeID == CFStringGetTypeID()) {
      CFType type = key;
      type.Unref();

      THROW_EXCEPTION("Cannot get value by specified key '%s'.", type.To<CFString>()->GetCString()->c_str());
    } else {
      THROW_EXCEPTION("Cannot get value by specified key.");
    }
  }

  return item;
}

Scoped<CFType> CFDictionary::GetValueOrNull(const void *key)
{
  CFTypeRef itemRef = CopyValueByKey(key);

  return Scoped<CFType>(new CFType(itemRef));
}

bool CFDictionary::HasValue(const void *key)
{
  if (CFDictionaryGetValue(handle, key) == NULL) {
    return false;
  }

  return true;
}
