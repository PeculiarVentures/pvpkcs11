#include "data.h"

using namespace osx;

CFIndex CFData::GetLength()
{
  return CFDataGetLength(handle);
}

const UInt8 *CFData::GetBytePtr()
{
  return CFDataGetBytePtr(handle);
}

Scoped<CFData> CFData::Create(CFAllocatorRef allocator, const UInt8 *bytes, CFIndex length)
{
  CFDataRef data = CFDataCreate(allocator, bytes, length);

  return Scoped<CFData>(new CFData(data));
}
