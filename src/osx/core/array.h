#pragma once

#include "./ref.h"

namespace osx
{

  class CFArray : public CFRef<CFArrayRef>
  {
  public:
    static Scoped<CFArray> Create(CFAllocatorRef allocator, const void **values, CFIndex numValues, const CFArrayCallBacks *callBacks);

    CFArray() : CFRef<CFArrayRef>() {}
    CFArray(CFTypeRef handle) : CFRef<CFArrayRef>(handle) {}

    CFIndex GetCount();
    Scoped<CFType> GetValue(CFIndex index);

  protected:
    const void *GetValueAtIndex(CFIndex index);
    CFTypeRef CopyValueAtIndex(CFIndex index);
    template <typename T>
    T CopyValueAtIndex(CFIndex index)
    {
      return (T)CopyValueAtIndex(index);
    }
  };

}