#pragma once

#include "string.h"

namespace osx
{

  class CFError : public CFRef<CFErrorRef>
  {
  public:
    CFError() : CFRef<CFErrorRef>() {}
    CFError(CFErrorRef handle) : CFRef<CFErrorRef>(handle) {}

    Scoped<CFString> GetDescription();
  };

}