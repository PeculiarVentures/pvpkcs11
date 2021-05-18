#include "error.h"

using namespace osx;

Scoped<CFString> CFError::GetDescription()
{
  CFStringRef str = CFErrorCopyDescription(handle);

  return Scoped<CFString>(new CFString(str));
}
