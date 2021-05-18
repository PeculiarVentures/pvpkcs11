#include "attr_dictionary.h"

using namespace osx;

CFTypeRef SecAttributeDictionary::GetValueRef()
{
  return reinterpret_cast<CFTypeRef>(GetValue(kSecValueRef));
}

CFTypeRef SecAttributeDictionary::CopyValueRef()
{
  CFTypeRef ref = GetValueRef();

  return CFRetain(ref);
}

Scoped<CFString> SecAttributeDictionary::GetClass()
{
  return GetValueCFString(kSecAttrLabel);
}

Scoped<CFString> SecAttributeDictionary::GetLabel()
{
  return GetValueCFString(kSecAttrLabel);
}

Scoped<CFData> SecAttributeDictionary::GetPublicKeyHash()
{
  return GetValueCFData(kSecAttrPublicKeyHash);
}

Scoped<CFData> SecAttributeDictionary::GetSubjectKeyId()
{
  return GetValueCFData(kSecAttrSubjectKeyID);
}

Scoped<CFData> SecAttributeDictionary::GetSerialNumber()
{
  return GetValueCFData(kSecAttrSerialNumber);
}