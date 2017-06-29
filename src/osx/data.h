#include "../stdafx.h"
#include "../core/objects/data.h"
#include <CoreFoundation/CoreFoundation.h>

namespace osx {
    
    const CFStringRef kSecClassData = CFStringCreateWithCString(NULL, "kSecData", kCFStringEncodingUTF8);
    
    class Data : public core::Data {
    };
    
}
