#pragma once

#include "../stdafx.h"

#include <CoreFoundation/CoreFoundation.h>

#include "../core/objects/data.h"
#include "helper.h"

namespace osx {
    
    const CFStringRef kSecClassData = CFStringCreateWithCString(NULL, "kSecData", kCFStringEncodingUTF8);
    
    class Data : public core::Data {
    public:
        void Assign
        (
         Scoped<Buffer>      data
         );
        CK_RV CreateValues
        (
         CK_ATTRIBUTE_PTR  pTemplate,
         CK_ULONG          ulCount
         );
        CK_RV CopyValues
        (
         Scoped<Object>    object,     /* the object which must be copied */
         CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
         CK_ULONG          ulCount     /* attributes in template */
        );
        CK_RV Destroy();
    protected:
    };
    
}
