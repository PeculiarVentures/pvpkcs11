#include "number.h"

using namespace osx;

Scoped<CFNumber> CFNumber::Create(CFAllocatorRef allocator, CFNumberType theType, const void *valuePtr)
{
  FUNCTION_BEGIN

  CFNumberRef num = CFNumberCreate(allocator, theType, valuePtr);

  return Scoped<CFNumber>(new CFNumber(num));

  FUNCTION_END
}

void CFNumber::GetValue(CFNumberType theType, void *valuePtr)
{
  FUNCTION_BEGIN

  if (!CFNumberGetValue(handle, theType, valuePtr))
  {
    THROW_EXCEPTION("Error on CFNumberGetValue");
  }

  FUNCTION_END
}
