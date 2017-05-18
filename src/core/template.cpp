#include "template.h"
#include "excep.h"

using namespace core;

Template::Template(
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG      ulTemplateLen
) :
    pTemplate(pTemplate),
    ulTemplateLen(ulTemplateLen)
{
}

CK_ULONG Template::Size()
{
    return ulTemplateLen;
}

CK_ATTRIBUTE_PTR Template::GetAttributeByIndex(CK_ULONG ulIndex)
{
    if (ulIndex > ulTemplateLen) {
        return NULL;
    }
    return &pTemplate[ulIndex];
}

CK_ATTRIBUTE_PTR Template::GetAttributeByType(CK_ULONG ulType)
{
    for (CK_ULONG ulIndex = 0; ulIndex < ulTemplateLen; ulIndex++) {
        CK_ATTRIBUTE_PTR attr = &pTemplate[ulIndex];
        if (attr && attr->type == ulType) {
            return attr;
        }
    }
    return NULL;
}

CK_ULONG Template::GetNumber(CK_ULONG ulType, CK_BBOOL bRequired, CK_ULONG ulDefaulValue)
{
    try {
        auto attr = GetAttributeByType(ulType);
        if (bRequired) {
            if (!attr) {
                std::string message = "Cannot get required attribute (" + std::to_string(ulType) + ")";
                THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, message.c_str());
            }
        }
        if (attr && attr->ulValueLen) {
            // Check size of attribute value
            if (attr->ulValueLen != sizeof(CK_ULONG)) {
                std::string message = "Attribute value is invalid (" + std::to_string(ulType) + ")";
                THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, message.c_str());
            }
            CK_ULONG dwResult;
            memcpy(&dwResult, attr->pValue, attr->ulValueLen);
            return dwResult;
        }
        else {
            return ulDefaulValue;
        }
    }
    CATCH_EXCEPTION;
}

CK_BBOOL Template::GetBool(CK_ULONG ulType, CK_BBOOL bRequired, CK_BBOOL bDefaulValue)
{
    try {
        auto attr = GetAttributeByType(ulType);
        if (bRequired) {
            if (!attr) {
                std::string message = "Cannot get required attribute (" + std::to_string(ulType) + ")";
                THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, message.c_str());
            }
        }
        if (attr && attr->ulValueLen) {
            // Check size of attribute value
            if (attr->ulValueLen != sizeof(CK_BBOOL)) {
                std::string message = "Attribute value is invalid (" + std::to_string(ulType) + ")";
                THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, message.c_str());
            }
            CK_BBOOL dwResult;
            memcpy(&dwResult, attr->pValue, attr->ulValueLen);
            return dwResult;
        }
        else {
            return bDefaulValue;
        }
    }
    CATCH_EXCEPTION;
}

Scoped<Buffer> Template::GetBytes(CK_ULONG ulType, CK_BBOOL bRequired, const char* cDefaultValue)
{
    try {
        auto attr = GetAttributeByType(ulType);
        if (bRequired) {
            if (!attr) {
                std::string message = "Cannot get required attribute (" + std::to_string(ulType) + ")";
                THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, message.c_str());
            }
        }
        Scoped<Buffer> result(new Buffer);
        if (attr->ulValueLen) {
            result->resize(attr->ulValueLen);
            memcpy(result->data(), attr->pValue, attr->ulValueLen);
        }
        else {
            result->resize(strlen(cDefaultValue));
            memcpy(result->data(), cDefaultValue, strlen(cDefaultValue));
        }
        return result;
    }
    CATCH_EXCEPTION;
}

bool Template::HasAttribute(
    CK_ATTRIBUTE_TYPE type
)
{
    return GetAttributeByType(type) != NULL;
}

CK_ATTRIBUTE_PTR Template::Get()
{
    return pTemplate;
}