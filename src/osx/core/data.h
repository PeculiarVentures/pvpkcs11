#pragma once

#include "./ref.h"

namespace osx
{

  class CFData : public CFRef<CFDataRef>
  {
  public:
    CFData() : CFRef<CFDataRef>() {}
    CFData(CFTypeRef handle) : CFRef<CFDataRef>(handle) {}

    static Scoped<CFData> Create(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length);

    CFIndex GetLength();
    const UInt8 *GetBytePtr();
  };

}