#include "array.h"

using namespace osx;

Scoped<CFArray> CFArray::Create(CFAllocatorRef allocator, const void **values, CFIndex numValues, const CFArrayCallBacks *callBacks)
{
  FUNCTION_BEGIN

  CFArrayRef ref = CFArrayCreate(allocator, values, numValues, callBacks);

  Scoped<CFArray> res = Scoped<CFArray>(new CFArray);
  res->Set(ref);

  return res;

  FUNCTION_END
}

CFIndex CFArray::GetCount()
{
  FUNCTION_BEGIN

  return CFArrayGetCount(this->handle);

  FUNCTION_END
}

const void *CFArray::GetValueAtIndex(CFIndex index)
{
  FUNCTION_BEGIN
  
  return CFArrayGetValueAtIndex(this->handle, index);

  FUNCTION_END
}

CFTypeRef CFArray::CopyValueAtIndex(CFIndex index)
{
  FUNCTION_BEGIN

  const void *item = GetValueAtIndex(index);

  return CFRetain((CFTypeRef)item);

  FUNCTION_END
}

Scoped<CFType> CFArray::GetValue(CFIndex index)
{
  FUNCTION_BEGIN

  CFTypeRef itemRef = CopyValueAtIndex(index);

  return Scoped<CFType>(new CFType(itemRef));

  FUNCTION_END
}
