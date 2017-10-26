#include "helper.h"

using namespace osx;

std::string osx::GetOSXErrorAsString
(
 OSStatus status,
 const char* funcName
 )
{
    CFRef<CFStringRef> osxMessage = SecCopyErrorMessageString(status, NULL);
    
    char message[1024];
    sprintf(message, "Error on %s %d. %s", funcName, status, CFStringGetCStringPtr(*osxMessage, kCFStringEncodingUTF8));
    
    return std::string(message, strlen(message));
}


CK_RV osx::SecItemDestroy(CFTypeRef item, CFStringRef itemClass)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status;
        
        CFRef<CFMutableDictionaryRef> matchAttrs = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                                0,
                                                                                &kCFTypeDictionaryKeyCallBacks,
                                                                                &kCFTypeDictionaryValueCallBacks);
        if (matchAttrs.IsEmpty()) {
            THROW_EXCEPTION("Error on CFDictionaryCreateMutable");
        }
        // kSecClass
        CFDictionarySetValue(*matchAttrs, kSecClass, itemClass);
        // kSecMatchItemList
        CFTypeRef items[] = {item};
        CFRef<CFArrayRef> cfItems = CFArrayCreate(kCFAllocatorDefault,
                                                  (const void **) &items,
                                                  1,
                                                  NULL);
        CFDictionaryAddValue(*matchAttrs, kSecMatchItemList, *cfItems);
        
        status = SecItemDelete(*matchAttrs);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecItemDelete");
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void osx::CopyObjectAttribute(core::Object* dst, core::Object * src, CK_ATTRIBUTE_TYPE type)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        if (!dst) {
            THROW_PARAM_REQUIRED_EXCEPTION("dst");
        }
        if (!src) {
            THROW_PARAM_REQUIRED_EXCEPTION("src");
        }
        
        Scoped<Buffer> buf = src->ItemByType(type)->ToBytes();
        dst->ItemByType(type)->SetValue(buf->data(), buf->size());
    }
    CATCH_EXCEPTION
}
