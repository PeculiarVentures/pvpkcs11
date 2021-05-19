#include "boolean.h"

using namespace osx;

Boolean CFBoolean::GetValue()
{
  FUNCTION_BEGIN

  return CFBooleanGetValue(handle);

  FUNCTION_END
}