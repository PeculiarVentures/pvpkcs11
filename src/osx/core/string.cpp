#include "./string.h"

using namespace osx;

CFIndex CFString::GetLength()
{
  return CFStringGetLength(handle);
}

const char *CFString::GetCStringPtr(CFStringEncoding encoding)
{
  return CFStringGetCStringPtr(handle, encoding);
}

CFComparisonResult CFString::Compare(CFStringRef string, CFStringCompareFlags compareOptions)
{
  return CFStringCompare(handle, string, compareOptions);
}

Scoped<std::string> CFString::GetCString(CFStringEncoding encoding)
{
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
}