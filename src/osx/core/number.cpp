#include "number.h"

using namespace osx;

Scoped<CFNumber> CFNumber::Create(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr)
{
  CFNumberRef num = CFNumberCreate(allocator, theType, valuePtr);
  
  return Scoped<CFNumber>(new CFNumber(num));
}
