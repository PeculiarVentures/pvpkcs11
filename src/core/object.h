#pragma once

#include "../stdafx.h"
#include "excep.h"
#include "template.h"
#include "attribute.h"

namespace core {

    class Object : public Attributes
    {
    public:

        CK_OBJECT_HANDLE    handle;

        Object();
        ~Object();

        virtual CK_RV GetValues
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV SetValues
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV GenerateValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV CopyValues(
            Scoped<Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV UnwrapValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

    protected:
        virtual CK_RV CreateValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

        virtual CK_RV GenerateValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

        virtual CK_RV GetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

        virtual CK_RV SetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

        virtual CK_RV CopyValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

        virtual CK_RV UnwrapValue
        (
            CK_ATTRIBUTE_PTR  attr
        );

    };

}
