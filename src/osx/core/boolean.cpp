#include "boolean.h"

using namespace osx;

Boolean CFBoolean::GetValue()
{
  return CFBooleanGetValue(handle);
}