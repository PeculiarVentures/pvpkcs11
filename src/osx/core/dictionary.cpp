#include "dictionary.h"

using namespace osx;

Scoped<CFDictionary> CFDictionary::Create(CFAllocatorRef allocator, CFDictionaryRef dict)
{
  FUNCTION_BEGIN

  CFDictionaryRef res = CFDictionaryCreateCopy(allocator, dict);
  if (res == nullptr)
  {
    THROW_EXCEPTION("Error on CFDictionaryCreateCopy");
  }

  return Scoped<CFDictionary>(new CFDictionary(res));

  FUNCTION_END
}

const void *CFDictionary::GetValueByKey(const void *key)
{
  FUNCTION_BEGIN

  const void *res = CFDictionaryGetValue(handle, key);

  return res;

  FUNCTION_END
}

Boolean CFDictionary::GetValueIfPresent(const void *key, const void **value)
{
  FUNCTION_BEGIN

  return CFDictionaryGetValueIfPresent(handle, key, value);
  
  FUNCTION_END
}

Scoped<CFType> CFDictionary::GetValue(const void *key)
{
  FUNCTION_BEGIN

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

  FUNCTION_END
}

Scoped<CFType> CFDictionary::GetValueOrNull(const void *key)
{
  FUNCTION_BEGIN

  CFType itemRef = GetValueByKey(key);
  itemRef.Unref();

  return itemRef.To<CFType>();

  FUNCTION_END
}

bool CFDictionary::HasValue(const void *key)
{
  FUNCTION_BEGIN

  if (CFDictionaryGetValue(handle, key) == NULL) {
    return false;
  }

  return true;

  FUNCTION_END
}
