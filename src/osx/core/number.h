#pragma once

#include "./ref.h"

namespace osx
{

  class CFNumber : public CFRef<CFNumberRef>
  {
  public:
    CFNumber() : CFRef<CFNumberRef>() {}
    CFNumber(CFTypeRef handle) : CFRef<CFNumberRef>(handle) {}

    static Scoped<CFNumber> Create(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr);
  };

}