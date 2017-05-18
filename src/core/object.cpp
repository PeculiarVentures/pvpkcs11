#include "object.h"

using namespace core;

Object::Object() :
    Attributes()
{
    Add(AttributeNumber::New(CKA_CLASS, 0, PVF_1));

    handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
}

Object::~Object()
{
}

CK_RV Object::GetValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR pAttribute = &pTemplate[i];

            // Check for SENSITIVE
            auto attribute = ItemByType(pAttribute->type);
            if (attribute->flags & PVF_7 &&
                ItemByType(CKA_SENSITIVE)->To<AttributeBool>()->ToValue() &&
                !ItemByType(CKA_EXTRACTABLE)->To<AttributeBool>()->ToValue()
                ) {
                THROW_PKCS11_ATTRIBUTE_SENSITIVE();
            }

            GetValue(pAttribute);
            ItemByType(pAttribute->type)->GetValue(pAttribute->pValue, &pAttribute->ulValueLen);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::GetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
    }
    CATCH_EXCEPTION
}

CK_RV Object::SetValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        // Check data
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR pAttribute = &pTemplate[i];
            // Check for EDITABLE
            auto attribute = ItemByType(pAttribute->type);
            if (!(attribute->flags & PVF_8)) {
                THROW_PKCS11_ATTRIBUTE_READ_ONLY();
            }
            SetValue(pAttribute);
        }

        // Set data
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            ItemByType(attr->type)->SetValue(attr->pValue, attr->ulValueLen);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::SetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
    }
    CATCH_EXCEPTION
}

CK_RV Object::CreateValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        Template tmpl(pTemplate, ulCount);

        for (CK_ULONG i = 0; i < Size(); i++) {
            auto attribute = ItemByIndex(i);
            if (attribute->flags & PVF_1 &&
                !tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            if (attribute->flags & PVF_2 &&
                tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCONSISTENT();
            }
        }

        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            CreateValue(attr);
        }

        // Set values
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            ItemByType(attr->type)->SetValue(attr->pValue, attr->ulValueLen);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::CreateValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
        switch (attr->type) {
        case CKA_CLASS: {
            // Must be equal to initialized value
            AttributeNumber attrClass(0, 0, 0);
            attrClass.SetValue(attr->pValue, attr->ulValueLen);
            if (ItemByType(CKA_CLASS)->To<AttributeNumber>()->ToValue() != attrClass.ToValue()) {
                THROW_PKCS11_ATTRIBUTE_VALUE_INVALID();
            }
            break;
        }
        }
    }
    CATCH_EXCEPTION
}

CK_RV Object::GenerateValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        Template tmpl(pTemplate, ulCount);

        for (CK_ULONG i = 0; i < Size(); i++) {
            auto attribute = ItemByIndex(i);
            if (attribute->flags & PVF_3 &&
                !tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            if (attribute->flags & PVF_4 &&
                tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCONSISTENT();
            }
        }

        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
        }

        // Set values
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            ItemByType(attr->type)->SetValue(attr->pValue, attr->ulValueLen);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::GenerateValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
    }
    CATCH_EXCEPTION
}

CK_RV Object::UnwrapValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        Template tmpl(pTemplate, ulCount);

        for (CK_ULONG i = 0; i < Size(); i++) {
            auto attribute = ItemByIndex(i);
            if (attribute->flags & PVF_5 &&
                !tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            if (attribute->flags & PVF_6 &&
                tmpl.HasAttribute(attribute->type)) {
                THROW_PKCS11_TEMPLATE_INCONSISTENT();
            }
        }

        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            UnwrapValue(attr);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::UnwrapValue(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {

    }
    CATCH_EXCEPTION
}

CK_RV Object::CopyValues
(
    Scoped<Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        // Check data
        if (!object->ItemByType(CKA_COPYABLE)->To<AttributeBool>()->ToValue()) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Object is not copyable");
        }
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR pAttribute = &pTemplate[i];
            // Check for properties which can be changed during copying
            auto attribute = ItemByType(pAttribute->type);
            if (!(attribute->flags & PVF_8 || attribute->flags & PVF_13)) {
                puts(attribute->Name().c_str());
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
            }
            CopyValue(pAttribute);
        }
        // Copy data from incoming object to current
        for (CK_ULONG i = 0; i < object->Size(); i++) {
            auto attr = object->ItemByIndex(i);
            ItemByType(attr->type)->SetValue(attr->Get(), attr->Size());
        }
        // Set data
        for (size_t i = 0; i < ulCount; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];
            ItemByType(attr->type)->SetValue(attr->pValue, attr->ulValueLen);
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV Object::CopyValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
    }
    CATCH_EXCEPTION
}