#include "key.h"

using namespace osx;

SecKeyRef osx::Key::Get()
{
    return *value;
}

SecKeyRef osx::SecKeyCopyPublicKeyEx(SecKeyRef key) {
    if (key == NULL) {
        return NULL;
    }
    LOGGER_DEBUG("%s Looking for public key SecKeyCopyPublicKey", __FUNCTION__);
    SecKeyRef pubKey = SecKeyCopyPublicKey(key);
    if (pubKey) {
        return pubKey;
    }
    
    CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(key);
    CFDataRef klbl = (CFDataRef)CFDictionaryGetValue(*attrs, kSecAttrApplicationLabel);
    if (klbl == NULL) {
        return NULL;
    }
    
    if (!pubKey) {
        LOGGER_DEBUG("%s Looking for public key in KeyChain by kSecAttrApplicationLabel", __FUNCTION__);
        // Get public key from key chain
        // create query
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassKey);
        CFDictionaryAddValue(*matchAttr, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFDictionaryAddValue(*matchAttr, kSecAttrApplicationLabel, klbl);
        CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitOne);
        
        SecItemCopyMatching(*matchAttr, (CFTypeRef*)&pubKey);
    }
    if (!pubKey) {
        LOGGER_DEBUG("%s Looking for public key in certificate from KeyChain by kSecAttrApplicationLabel", __FUNCTION__);
        // Get public key from certificate
        // create query
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(*matchAttr, kSecClass, kSecClassCertificate);
        CFDictionaryAddValue(*matchAttr, kSecAttrPublicKeyHash, klbl);
        CFDictionaryAddValue(*matchAttr, kSecReturnRef, kCFBooleanTrue);
        CFDictionaryAddValue(*matchAttr, kSecMatchLimit, kSecMatchLimitOne);
        
        CFRef<SecCertificateRef> cert;
        OSStatus status = SecItemCopyMatching(*matchAttr, (CFTypeRef*)&cert);
        if (!(status || cert.IsEmpty())) {
            status = SecCertificateCopyPublicKey(*cert, &pubKey);
            if (status) {
                std::string error = GetOSXErrorAsString(status, "SecCertificateCopyPublicKey");
                LOGGER_DEBUG("%s %s", __FUNCTION__, error.c_str());
            }
        } else {
            pubKey = NULL;
        }
    }
    if (pubKey == NULL) {
        LOGGER_WARN("%s Cannot copy public key", __FUNCTION__);
    }
    return pubKey;
}
