#pragma once

#include "dictionary.h"

namespace osx
{

  class CFMutableDictionary : public CFDictionary
  {
  public:
    CFMutableDictionary() : CFDictionary() {}
    CFMutableDictionary(CFTypeRef _Nonnull handle) : CFDictionary(handle) {}

    static Scoped<CFMutableDictionary> Create(
        CFAllocatorRef _Nullable allocator = kCFAllocatorDefault,
        CFIndex capacity = 0,
        const CFDictionaryKeyCallBacks * _Nonnull keyCallBacks = &kCFTypeDictionaryKeyCallBacks,
        const CFDictionaryValueCallBacks * _Nonnull valueCallBacks = &kCFTypeDictionaryValueCallBacks);
    static Scoped<CFMutableDictionary> CreateMutable(CFAllocatorRef _Nullable allocator, CFIndex capacity, CFDictionaryRef _Nonnull dict);
    CFMutableDictionary * _Nonnull AddValue(const void * _Nonnull key, const void *  _Nonnull value);
    CFMutableDictionary * _Nonnull SetValue(const void * _Nonnull key, const void * _Nonnull value);
  };

}