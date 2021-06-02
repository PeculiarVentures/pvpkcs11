#pragma once

#include "excep.h"

namespace osx
{

  template <typename T>
  class CFRef
  {
  public:
    CFRef() : handle(NULL), dispose(true) {}

    CFRef(CFTypeRef _Nullable value, bool dispose = true) : handle((T)value), dispose(dispose) {}

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
      FUNCTION_BEGIN

      if (IsEmpty())
      {
        THROW_EXCEPTION("CFRef has nullable handle");
      }
      return handle;
      
      FUNCTION_END
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
      if (IsEmpty()) {
        return NULL;
      }
      
      return (T)CFRetain(handle);
    }

    Boolean IsEqual(CFTypeRef _Nullable value)
    {
      return CFEqual(handle, value);
    }

    void Show()
    {
      CFShow(this->handle);
    }

    CFTypeID GetTypeID()
    {
      return CFGetTypeID(handle);
    }

    template <class C>
    Scoped<C> To()
    {
      T typePtr = Retain();

      return Scoped<C>(new C(typePtr));
    }

  protected:
    T handle;
    bool dispose;
  };

  using CFType = CFRef<CFTypeRef>;

}
