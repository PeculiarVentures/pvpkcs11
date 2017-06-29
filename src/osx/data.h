#include "../stdafx.h"
#include "../core/objects/data.h"
#include <CoreFoundation/CoreFoundation.h>

namespace osx {
    
    const CFStringRef kSecClassData = CFStringCreateWithCString(NULL, "kSecData", kCFStringEncodingUTF8);
    
    class Data : public core::Data {
    public:
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
    };
    
}
