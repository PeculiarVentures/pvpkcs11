#include "debug.h"
#include "core/name.h"

std::string printTemplate
(
 CK_ATTRIBUTE_PTR pTmpl,
 CK_ULONG               ulTmplLen
 )
{
    std::string res = "[";
    
    if (pTmpl) {
        for (CK_ULONG i = 0; i < ulTmplLen; i++) {
            CK_ATTRIBUTE_PTR attr = &pTmpl[i];
            const char* attrName = core::Name::getAttribute(attr->type);
            if (i) {
                res += ", ";
            }
            if (attrName) {
                res += attrName;
            } else {
                char buf[11] = {0};
                sprintf(buf, "0x%08lX", attr->type);
                res += buf;
            }
        }
    }
    
    res += "]";
    
    return res;
}

std::string printAddress
(
 CK_VOID_PTR            pValue
 )
{
    std::string res = "NULL";
    if (pValue) {
        char buf[20] = {0};
        sprintf(buf, "0x%p", pValue);
        res = buf;
    }
    return res;
}

std::string printHandle
(
 CK_ULONG               ulHandle
 )
{
    std::string res = "NULL";
    
    char buf[11] = {0};
    sprintf(buf, "0x%08lX", ulHandle);
    res = buf;
    
    return res;
}

std::string printMechanismType
(
 CK_MECHANISM_TYPE      mechType
 )
{
    char buf[256] = { 0 };
    sprintf(buf, "%s(0x%08lX)", core::Name::getMechanism(mechType), mechType);
    return std::string(buf);
}