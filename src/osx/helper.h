#pragma once

#include "../stdafx.h"
#include "../core/excep.h"
#include "../core/object.h"
#include "./core/ref.h"

#include <CoreFoundation/CoreFoundation.h>
#include <Security/Security.h>

namespace osx {
    
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
