#pragma once

#include "excep.h"

namespace osx
{

  template <typename T>
  class CFRef
  {
  public:
    CFRef() : handle(NULL), dispose(true) {}

    CFRef(T _Nullable value, bool dispose = true) : handle(value), dispose(dispose) {}

    ~CFRef()
    {
      Release();
    }

    void Unref()
    {
      dispose = false;
    }

    void Release()
    {
      if (!IsEmpty() && dispose)
      {
        CFIndex retainCount = CFGetRetainCount(handle);
        CFRelease(handle);
        if (retainCount == 1)
        {
          handle = NULL;
        }
      }
    }

    T _Nonnull Get()
    {
      if (IsEmpty())
      {
        THROW_EXCEPTION("CFRef has nullable handle");
      }
      return handle;
    }

    T _Nonnull operator*()
    {
      return Get();
    }

    T *_Nullable Ref()
    {
      return &handle;
    }

    T *_Nullable operator&()
    {
      return &handle;
    }

    void Set(T _Nullable value)
    {
      if (value != handle)
      {
        handle = value;
      }
    }

    CFRef<T> &operator=(const T _Nullable data)
    {
      Set(data);
      return *this;
    }

    Boolean IsEmpty()
    {
      return !handle;
    }

    T Retain()
    {
      return (T)CFRetain(Get());
    }

    Boolean IsEqual(CFTypeRef _Nullable value)
    {
      return CFEqual(handle, value);
    }

    void Show() {
      CFShow(this->handle);
    }

  protected:
    T handle;
    bool dispose;
  };

}
