#pragma once

#include "../core.h"

#include <Security/SecAsn1Coder.h>

namespace osx
{

  class SecAsn1Coder
  {
  public:
    SecAsn1Coder();
    ~SecAsn1Coder();

    static Scoped<SecAsn1Coder> Create();

    static SecAsn1Item FromCFData(CFData *data);
    SecAsn1Item EncodeItem(const void *src, const SecAsn1Template *templates);
    void DecodeItem(
        const void *src, // DER-encoded source
        size_t len,
        const SecAsn1Template *templates,
        void *dest);
    void Release();

  protected:
    SecAsn1CoderRef handle;
  };

}