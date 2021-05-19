#include "attr_dictionary.h"

using namespace osx;

CFTypeRef SecAttributeDictionary::GetValueRef()
{
  return reinterpret_cast<CFTypeRef>(GetValueByKey(kSecValueRef));
}

CFTypeRef SecAttributeDictionary::CopyValueRef()
{
  CFTypeRef ref = GetValueRef();

  return CFRetain(ref);
}

Scoped<CFString> SecAttributeDictionary::GetClass()
{
  return GetValue(kSecAttrLabel)->To<CFString>();
}

Scoped<CFString> SecAttributeDictionary::GetLabel()
{
  return GetValue(kSecAttrLabel)->To<CFString>();
}

Scoped<CFData> SecAttributeDictionary::GetPublicKeyHash()
{
  return GetValue(kSecAttrPublicKeyHash)->To<CFData>();
}

Scoped<CFData> SecAttributeDictionary::GetSubjectKeyId()
{
  return GetValue(kSecAttrSubjectKeyID)->To<CFData>();
}

Scoped<CFData> SecAttributeDictionary::GetSerialNumber()
{
  return GetValue(kSecAttrSerialNumber)->To<CFData>();
}