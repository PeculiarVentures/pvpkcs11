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

SecAccessRef osx::SecAccessCreateEmptyList(CFStringRef description) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status = errSecSuccess;
        
        CFRef<CFMutableArrayRef> appList = CFArrayCreateMutable(kCFAllocatorDefault, 0, &kCFTypeArrayCallBacks);
        CFRef<SecAccessRef> access;
        status = SecAccessCreate(description, *appList, &access);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecAccessCreate");
        }
        
        return access.Retain();
    }
    CATCH_EXCEPTION
}

CFDictionaryRef _Nullable osx::SecKeyCopyAttributesEx(SecKeyRef _Nonnull key) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status = errSecSuccess;
        CFRef<CFDictionaryRef> res;
        
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION("key");
        }
        
        // get attributes from keychain item
        
        CFRef<CFMutableDictionaryRef> query = CFDictionaryCreateMutable();
        CFDictionarySetValue(*query, kSecValueRef, key);
        CFDictionarySetValue(*query, kSecClass, kSecClassKey);
        CFDictionarySetValue(*query, kSecReturnAttributes, kCFBooleanTrue);
        CFDictionarySetValue(*query, kSecMatchLimit, kSecMatchLimitOne);
        
        status = SecItemCopyMatching(*query, (CFTypeRef*)&res);
        if (!status) {
            return res.Retain();
        }
        
        LOGGER_DEBUG("%s", GetOSXErrorAsString(status, "SecItemCopyMatching").c_str());
        
        // get attributes via standard SecKeyCopyAttributesEx function
        
        return SecKeyCopyAttributes(key);
    }
    CATCH_EXCEPTION
}

SecKeyRef _Nullable osx::SecKeyCopyPublicKeyEx(SecKeyRef _Nonnull key) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status = errSecSuccess;
        
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION(key);
        }
        
        // Tries to get public key from certificate by kSecAttrSubjectKeyID
        CFRef<CFDataRef> appLabel = SecKeyCopyApplicationLabel(key);
        if (!appLabel.IsEmpty()) {
            CFRef<CFMutableDictionaryRef> query = CFDictionaryCreateMutable();
            CFDictionarySetValue(*query, kSecAttrSubjectKeyID, *appLabel);
            CFDictionarySetValue(*query, kSecClass, kSecClassCertificate);
            CFDictionarySetValue(*query, kSecReturnRef, kCFBooleanTrue);
            CFDictionarySetValue(*query, kSecMatchLimit, kSecMatchLimitOne);
            
            CFRef<SecCertificateRef> cert;
            status = SecItemCopyMatching(*query, (CFTypeRef*)&cert);
            if (status == errSecSuccess) {
                CFRef<SecKeyRef> publicKey = SecCertificateCopyKey(*cert);
                if (publicKey.IsEmpty()) {
                    LOGGER_DEBUG("%s", GetOSXErrorAsString(status, "SecCertificateCopyKey").c_str());
                }
            } else {
                LOGGER_DEBUG("%s", GetOSXErrorAsString(status, "SecItemCopyMatching").c_str());
            }
        }
        
        // Uses standard SecKeyCopyPublicKey function
        
        return SecKeyCopyPublicKey(key);
    }
    CATCH_EXCEPTION
}

CFDataRef _Nullable osx::SecKeyCopyApplicationLabel(SecKeyRef _Nonnull key) {
    LOGGER_FUNCTION_BEGIN;
    
    try {
        if (!key) {
            THROW_PARAM_REQUIRED_EXCEPTION(key);
        }
        
        CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributesEx(key);
        if (attrs.IsEmpty()) {
            return NULL;
        }
        
        CFDataRef applicationLabel = (CFDataRef) CFDictionaryGetValue(*attrs, kSecAttrApplicationLabel);
        
        if (applicationLabel) {
            applicationLabel = CFDataCreateCopy(kCFAllocatorDefault, applicationLabel);
        }
        return applicationLabel;
    }
    CATCH_EXCEPTION
}
