#include "data.h"

#include "helper.h"
#include <Security/SecItem.h>

using namespace osx;

CK_RV Data::CreateValues
(
 CK_ATTRIBUTE_PTR  pTemplate,
 CK_ULONG          ulCount
 )
{
    try {
        core::Data::CreateValues(pTemplate,
                                 ulCount);
        
        core::Template tmpl(pTemplate, ulCount);
        auto attrValue = tmpl.GetBytes(CKA_VALUE, true);
        
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecClass, kSecClassData);
        Scoped<Buffer> dataBuf = tmpl.GetBytes(CKA_VALUE, true);
        CFRef<CFDataRef> data = CFDataCreate(NULL, dataBuf->data(), dataBuf->size());
        const CFDataRef dataArray[] = { &data };
        CFRef<CFArrayRef> datas = CFArrayCreate(NULL, (const void **)dataArray, 1, &kCFTypeArrayCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecMatchItemList, &datas);
        CFRef<CFStringRef> label = CFStringCreateWithCString(NULL, "WOW", kCFStringEncodingUTF8);
        CFDictionaryAddValue(&matchAttr, kSecAttrLabel, &label);
        
        CFTypeRef type = NULL;
        OSStatus status = SecItemAdd(&matchAttr, &type);
        if (status) {
            fprintf(stdout, "OSStatus: %lu\n", status);
            THROW_EXCEPTION("Error on SecItemAdd");
        }
        
        puts("Success");
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Data::CopyValues
(
 Scoped<core::Object>    object,
 CK_ATTRIBUTE_PTR  pTemplate,
 CK_ULONG          ulCount   
 )
{
    try {
        core::Data::CopyValues(
                               object,
                               pTemplate,
                               ulCount
                               );
        
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

CK_RV Data::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
