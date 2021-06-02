#pragma once

#include "./ref.h"

namespace osx
{

  class CFBoolean : public CFRef<CFBooleanRef>
  {
  public:
    CFBoolean() : CFRef<CFBooleanRef>() {}
    CFBoolean(CFTypeRef handle) : CFRef<CFBooleanRef>(handle) {}

    Boolean GetValue();
  };

}