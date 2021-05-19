#pragma once

#include "string.h"

namespace osx
{

  class CFError : public CFRef<CFErrorRef>
  {
  public:
    CFError() : CFRef<CFErrorRef>() {}
    CFError(CFTypeRef handle) : CFRef<CFErrorRef>(handle) {}

    Scoped<CFString> GetDescription();
  };

}