#pragma once

#include "../stdafx.h"

namespace core {

    class Template {

    public:
        Template(
            CK_ATTRIBUTE_PTR pTemplate,
            CK_ULONG      ulTemplateLen
        );

        CK_ULONG Size();
        CK_ATTRIBUTE_PTR Get();

        bool HasAttribute(
            CK_ATTRIBUTE_TYPE type
        );

        CK_ATTRIBUTE_PTR GetAttributeByIndex(CK_ULONG ulIndex);
        CK_ATTRIBUTE_PTR GetAttributeByType(CK_ULONG ulType);

        CK_ULONG GetNumber(CK_ULONG ulType, CK_BBOOL bRequired, CK_ULONG ulDefaulValue = 0);
        CK_BBOOL GetBool(CK_ULONG ulType, CK_BBOOL bRequired, CK_BBOOL bDefaulValue = false);
        Scoped<Buffer> GetBytes(CK_ULONG ulType, CK_BBOOL bRequired, const char* cDefaultValue = "");
        Scoped<std::string> GetString(CK_ULONG ulType, CK_BBOOL bRequired, const char* cDefaultValue = "");

    protected:
        CK_ATTRIBUTE_PTR pTemplate;
        CK_ULONG         ulTemplateLen;
    };

}
