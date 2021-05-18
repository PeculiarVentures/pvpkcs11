#include "array.h"

using namespace osx;

Scoped<CFArray> CFArray::Create(CFAllocatorRef allocator, const void **values, CFIndex numValues, const CFArrayCallBacks *callBacks)
{
  CFArrayRef ref = CFArrayCreate(allocator, values, numValues, callBacks);

  Scoped<CFArray> res = Scoped<CFArray>(new CFArray);
  res->Set(ref);

  return res;
}

CFIndex CFArray::GetCount()
{
  return CFArrayGetCount(this->handle);
}

const void *CFArray::GetValueAtIndex(CFIndex index)
{
  return CFArrayGetValueAtIndex(this->handle, index);
}

CFTypeRef CFArray::CopyValueAtIndex(CFIndex index)
{
  const void *item = GetValueAtIndex(index);

  return CFRetain((CFTypeRef)item);
}
