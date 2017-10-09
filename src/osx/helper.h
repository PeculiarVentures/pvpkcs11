#pragma once

#include "../stdafx.h"
#include "../core/excep.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

namespace osx {
    
    std::string GetOSXErrorAsString(OSStatus status, const char* funcName);
    
#define OSX_EXCEPTION_NAME "OSXException"
    
#define THROW_OSX_EXCEPTION(status, funcName)                                        \
throw Scoped<core::Exception>(new core::Pkcs11Exception(OSX_EXCEPTION_NAME, CKR_FUNCTION_FAILED, GetOSXErrorAsString(status, funcName).c_str(), __FUNCTION__, __FILE__, __LINE__))
    
    template<typename T>
    class CFRef {
    public:
        CFRef() : value(NULL), free(CFRelease) {
            LOGGER_TRACE("CFRef init value:%p %s", value, typeid(value).name());
        }
        
        CFRef(T value) : value(value), free(CFRelease) {
            LOGGER_TRACE("CFRef init value:%p %s", value, typeid(value).name());
        }
        
        CFRef(T value, void (*free)(const void* ref)) : value(value), free(free) {
            LOGGER_TRACE("CFRef init value:%p %s", value, typeid(value).name());
        }
        
        ~CFRef(){
            if (value && free) {
                LOGGER_TRACE("CFRef relese value:%p %s", value, typeid(value).name());
                free(value);
                value = NULL;
            }
        }
        
        T Get() {
            return value;
        }
        
        CFRef<T>& operator=(const T data) {
            LOGGER_TRACE("Set value:%p %s", data, typeid(value).name());
            value = data;
            return *this;
        }
        
        T* operator&() {
            return &value;
        }
        
        T operator*() {
            return value;
        }
        
        T get() {
            return value;
        }
        
        bool IsEmpty() {
            return value == NULL;
        }
        
    protected:
        T value;
        void (*free)(const void* ref);
    };
    
    static CFStringRef kSecAttrLabelModule = (CFSTR("WebCrypto Local"));
    
    CK_RV SecItemDestroy(void* item);

}


