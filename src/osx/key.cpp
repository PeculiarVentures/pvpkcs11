#include "key.h"

using namespace osx;

SecKeyRef osx::Key::Get()
{
    return &value;
}

SecKeyRef osx::SecKeyCopyPublicKeyEx(SecKeyRef key) {
    if (key == NULL) {
        return NULL;
    }
    SecKeyRef pubKey = SecKeyCopyPublicKey(key);
    if (pubKey) {
        return pubKey;
    }
    
    CFRef<CFDictionaryRef> attrs = SecKeyCopyAttributes(key);
    CFDataRef klbl = (CFDataRef)CFDictionaryGetValue(&attrs, kSecAttrApplicationLabel);
    if (klbl == NULL) {
        return NULL;
    }
    
    if (!pubKey) {
        // Get public key from key chain
        // create query
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecClass, kSecClassKey);
        CFDictionaryAddValue(&matchAttr, kSecAttrKeyClass, kSecAttrKeyClassPublic);
        CFDictionaryAddValue(&matchAttr, kSecAttrApplicationLabel, klbl);
        CFDictionaryAddValue(&matchAttr, kSecReturnRef, kCFBooleanTrue);
        
        SecItemCopyMatching(&matchAttr, (CFTypeRef*)&pubKey);
    }
    if (!pubKey) {
        // Get public key from certificate
        // Get public key from key chain
        // create query
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecClass, kSecClassCertificate);
        CFDictionaryAddValue(&matchAttr, kSecAttrApplicationLabel, klbl);
        CFDictionaryAddValue(&matchAttr, kSecReturnRef, kCFBooleanTrue);
        
        SecCertificateRef cert = NULL;
        SecItemCopyMatching(&matchAttr, (CFTypeRef*)&cert);
        if (cert) {
            SecCertificateCopyPublicKey(cert, &pubKey);
            CFRelease(cert);
        }
    }
    return pubKey;
}
