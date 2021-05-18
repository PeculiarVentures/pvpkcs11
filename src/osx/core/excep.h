#include "../../stdafx.h"
#include "../../core/excep.h"
#include "../../core/object.h"

#include <CoreFoundation/CoreFoundation.h>

namespace osx
{

  std::string GetOSXErrorAsString(OSStatus status, const char *_Nonnull funcName);
  void CopyObjectAttribute(core::Object *_Nonnull dst, core::Object *_Nonnull src, CK_ATTRIBUTE_TYPE type);

#define OSX_EXCEPTION_NAME "OSXException"

#define THROW_OSX_EXCEPTION(status, funcName) \
  throw Scoped<core::Exception>(new core::Pkcs11Exception(OSX_EXCEPTION_NAME, CKR_FUNCTION_FAILED, GetOSXErrorAsString(status, funcName).c_str(), __FUNCTION__, __FILE__, __LINE__))

}
