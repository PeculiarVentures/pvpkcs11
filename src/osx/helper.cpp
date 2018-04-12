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


void osx::SecItemDestroy(CFTypeRef item)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status;
        
        if (!item) {
            THROW_PARAM_REQUIRED_EXCEPTION("item");
        }
        
        CFRef<CFMutableDictionaryRef> matchAttrs = CFDictionaryCreateMutable();
        
        CFRef<CFStringRef> itemClass;
        CFTypeID itemTypeID = CFGetTypeID(item);
        if (itemTypeID == SecKeyGetTypeID()) {
            itemClass = kSecClassKey;
        } else if (itemTypeID == SecCertificateGetTypeID()) {
            itemClass = kSecClassCertificate;
        }
        
        // kSecClass
        CFDictionarySetValue(*matchAttrs, kSecClass, *itemClass);
        // kSecMatchItemList
        const void * items[] = { item };
        CFRef<CFArrayRef> cfItems = CFArrayCreate(kCFAllocatorDefault,
                                                  items,
                                                  ARRAY_SIZE(items),
                                                  &kCFTypeArrayCallBacks);
        CFDictionarySetValue(*matchAttrs, kSecMatchItemList, *cfItems);
        
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

CFMutableDictionaryRef osx::CFDictionaryCreateMutable() {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        return CFDictionaryCreateMutable(kCFAllocatorDefault,
                                         0,
                                         &kCFTypeDictionaryKeyCallBacks,
                                         &kCFTypeDictionaryValueCallBacks);
    }
    CATCH_EXCEPTION
}
