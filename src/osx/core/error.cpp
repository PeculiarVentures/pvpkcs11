#include "error.h"

using namespace osx;

Scoped<CFString> CFError::GetDescription()
{
  FUNCTION_BEGIN
  
  CFStringRef str = CFErrorCopyDescription(handle);

  return Scoped<CFString>(new CFString(str));

  FUNCTION_END
}
