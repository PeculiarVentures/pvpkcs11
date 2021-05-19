#include "./string.h"

using namespace osx;

CFIndex CFString::GetLength()
{
  FUNCTION_BEGIN
  
  return CFStringGetLength(handle);

  FUNCTION_END
}

const char *CFString::GetCStringPtr(CFStringEncoding encoding)
{
  FUNCTION_BEGIN
  
  return CFStringGetCStringPtr(handle, encoding);

  FUNCTION_END
}

CFComparisonResult CFString::Compare(CFStringRef string, CFStringCompareFlags compareOptions)
{
  FUNCTION_BEGIN

  return CFStringCompare(handle, string, compareOptions);

  FUNCTION_END
}

Scoped<std::string> CFString::GetCString(CFStringEncoding encoding)
{
  FUNCTION_BEGIN

  Scoped<std::string> res = Scoped<std::string>(new std::string());
  const char *cstr = GetCStringPtr(encoding);

  if (cstr == NULL)
  {
    CFIndex cstrLen = GetLength();
    res->resize(cstrLen);

    CFIndex usedBytes = 0L;
    CFStringGetBytes(Get(), CFRangeMake(0L, cstrLen), kCFStringEncodingUTF8, '?', false, (UInt8 *)res->data(), cstrLen, &usedBytes);
    res->resize(usedBytes);
  }
  else
  {
    res = Scoped<std::string>(new std::string(cstr));
  }

  return res;

  FUNCTION_END
}