#pragma once

#include "../stdafx.h"
#include "../core/excep.h"
#include "../core/object.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

namespace osx {
    
    std::string GetOSXErrorAsString(OSStatus status, const char * _Nonnull funcName);
    void CopyObjectAttribute(core::Object * _Nonnull dst, core::Object * _Nonnull src, CK_ATTRIBUTE_TYPE type);
    
#define OSX_EXCEPTION_NAME "OSXException"
    
#define THROW_OSX_EXCEPTION(status, funcName)                                        \
throw Scoped<core::Exception>(new core::Pkcs11Exception(OSX_EXCEPTION_NAME, CKR_FUNCTION_FAILED, GetOSXErrorAsString(status, funcName).c_str(), __FUNCTION__, __FILE__, __LINE__))
    
    template<typename T>
    class CFRef {
    public:
        CFRef() : handle(NULL) {}
        
        CFRef(T _Nullable value) : handle(value) {}
        
        ~CFRef(){
            Release();
        }
        
        void Release() {
            if (!IsEmpty()) {
                CFIndex retainCount = CFGetRetainCount(handle);
                CFRelease(handle);
                if (retainCount == 1) {
                    handle = NULL;
                }
            }
        }
        
        T _Nonnull Get() {
            if (IsEmpty()) {
                THROW_EXCEPTION("CFRef has nullable handle");
            }
            return handle;
        }
        
        T _Nonnull operator*() {
            return Get();
        }
        
        T* _Nullable Ref() {
            return &handle;
        }
        
        T* _Nullable operator&() {
            return &handle;
        }
        
        void Set(T _Nullable value) {
            if (value != handle) {
                handle = value;
            }
        }
        
        CFRef<T>& operator=(const T _Nullable data) {
            Set(data);
            return *this;
        }
        
        Boolean IsEmpty() {
            return !handle;
        }
        
        T Retain() {
            return (T) CFRetain(Get());
        }
        
        Boolean IsEqual(CFTypeRef _Nullable value) {
            return CFEqual(handle, value);
        }
        
    protected:
        T handle;
    };
    
    static const CFStringRef _Nonnull kSecAttrLabelModule = (CFSTR("WebCrypto Local"));
    
    /*!
     @function SecItemDestroy
        Removes item from keychain
     
     @param item
        SecKey and SecCertificate which must be removed
     */
    void SecItemDestroy(CFTypeRef _Nonnull item);

    /*!
     @function CFDictionaryCreateMutable
        Creates a new empty mutable dictionary
     
     @result
        A reference to the new mutable CFDictionary.
    */
    CFMutableDictionaryRef _Nonnull CFDictionaryCreateMutable();
    
    /*!
     @function SecAccessCreateEmptyList
        Creates a new SecAccessRef
     @param description
        The name of the item as it should appear in security dialogs
     @result
        new instance of SecAccess
     */
    SecAccessRef _Nonnull SecAccessCreateEmptyList(CFStringRef _Nonnull description);
    
    /*!
     @function SecAccessCreateEmptyList
        Returns dictionary of key attributes
     @param key
        The key from which to retrieve attributes
     @result
        dictionary of attributes
     @note
        1. Tries to get attributes from keychain item
        2. Uses standard SecKeyCopyAttributes function
     */
    CFDictionaryRef _Nullable SecKeyCopyAttributesEx(SecKeyRef _Nonnull key);
    
    /*!
     @function SecKeyCopyPublicKeyEx
        Retrieves the public key from a key.
     @param key
        The key from which to retrieve a public key
     @result
        public key
     @note
         1. Tries to get public key from certificate by kSecAttrSubjectKeyID
         2. Uses standard SecKeyCopyPublicKey function
     */
    SecKeyRef _Nullable SecKeyCopyPublicKeyEx(SecKeyRef _Nonnull key);
    
    /*!
     @function SecKeyCopyApplicationLabel
        Retrieves the application label attribute from a key.
     @param key
        The key from which to retrieve an application label attribute
     @result
        CFDataRef application label attribute
     */
    CFDataRef _Nullable SecKeyCopyApplicationLabel(SecKeyRef _Nonnull key);

}
