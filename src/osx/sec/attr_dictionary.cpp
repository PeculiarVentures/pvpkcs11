#include "attr_dictionary.h"

using namespace osx;

Scoped<CFType> SecAttributeDictionary::GetValueRef()
{
  FUNCTION_BEGIN

  CFType valueRef = reinterpret_cast<CFTypeRef>(GetValueByKey(kSecValueRef));
  valueRef.Unref();

  return valueRef.To<CFType>();

  FUNCTION_END
}

Scoped<CFString> SecAttributeDictionary::GetClass()
{
  FUNCTION_BEGIN

  return GetValue(kSecAttrLabel)->To<CFString>();

  FUNCTION_END
}

Scoped<CFString> SecAttributeDictionary::GetLabel()
{
  FUNCTION_BEGIN

  return GetValue(kSecAttrLabel)->To<CFString>();

  FUNCTION_END
}

Scoped<CFData> SecAttributeDictionary::GetPublicKeyHash()
{
  FUNCTION_BEGIN

  return GetValue(kSecAttrPublicKeyHash)->To<CFData>();

  FUNCTION_END
}

Scoped<CFData> SecAttributeDictionary::GetSubjectKeyId()
{
  FUNCTION_BEGIN

  return GetValue(kSecAttrSubjectKeyID)->To<CFData>();

  FUNCTION_END
}

Scoped<CFData> SecAttributeDictionary::GetSerialNumber()
{
  FUNCTION_BEGIN

  return GetValue(kSecAttrSerialNumber)->To<CFData>();

  FUNCTION_END
}