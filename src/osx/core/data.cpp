#include "data.h"

using namespace osx;

CFIndex CFData::GetLength()
{
  FUNCTION_BEGIN

  return CFDataGetLength(handle);

  FUNCTION_END
}

const UInt8 *CFData::GetBytePtr()
{
  FUNCTION_BEGIN

  return CFDataGetBytePtr(handle);

  FUNCTION_END
}

Scoped<CFData> CFData::Create(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length)
{
  FUNCTION_BEGIN

  CFDataRef data = CFDataCreate(allocator, bytes, length);

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}
