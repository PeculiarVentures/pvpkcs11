#pragma once

#include "./ref.h"

namespace osx
{

  class CFString : public CFRef<CFStringRef>
  {
  public:

    CFString() : CFRef<CFStringRef>() {}
    CFString(CFStringRef handle) : CFRef<CFStringRef>(handle) {}

    CFIndex GetLength();
    const char *GetCStringPtr(CFStringEncoding encoding = kCFStringEncodingUTF8);
    Scoped<std::string> GetCString(CFStringEncoding encoding = kCFStringEncodingUTF8);
    CFComparisonResult Compare(CFStringRef string, CFStringCompareFlags compareOptions);
  };

}