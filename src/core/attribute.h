#pragma once

#include "../stdafx.h"
#include "excep.h"
#include "collection.h"

namespace core {
    // 1
    // Must be specified when object is created with C_CreateObject.
#define PVF_1       0x00000001
    // 2
    // Must not be specified when object is created with C_CreateObject.
#define PVF_2       0x00000002
    // 3
    // Must be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
#define PVF_3       0x00000004
    // 4	
    // Must not be specified when object is generated with C_GenerateKey or C_GenerateKeyPair.
#define PVF_4       0x00000008
    // 5	
    // Must be specified when object is unwrapped with C_UnwrapKey.
#define PVF_5       0x00000010
    // 6	
    // Must not be specified when object is unwrapped with C_UnwrapKey.
#define PVF_6       0x00000020
    // 7	
    // Cannot be revealed if object has its CKA_SENSITIVE attribute set to CK_TRUE 
    // or its CKA_EXTRACTABLE attribute set to CK_FALSE.
#define PVF_7       0x00000040
    // 8	
    // May be modified after object is created with a C_SetAttributeValue call, 
    // or in the process of copying object with a C_CopyObject call. 
    // However, it is possible that a particular token may not permit modification 
    // of the attribute during the course of a C_CopyObject call.
#define PVF_8       0x00000080
    // 9	
    // Default value is token - specific, and may depend on the values of other attributes.
#define PVF_9       0x00000100
    // 10	
    // Can only be set to CK_TRUE by the SO user.
#define PVF_10      0x00000200
    // 11	
    // Attribute cannot be changed once set to CK_TRUE.It becomes a read only attribute.
#define PVF_11      0x00000400
    // 12	
    // Attribute cannot be changed once set to CK_FALSE.It becomes a read only attribute.
#define PVF_12      0x00000800

    class Attribute {
    public:
        CK_ATTRIBUTE_TYPE type;
        CK_ULONG          flags;

        Attribute(
            CK_ATTRIBUTE_TYPE   type,
            CK_ULONG            flags
        ) :
            type(type),
            flags(flags)
        {}

        virtual CK_ULONG Size() = 0;
        virtual void GetValue(CK_VOID_PTR pData, CK_ULONG_PTR pulDataLen) = 0;
        virtual void SetValue(CK_VOID_PTR pData, CK_ULONG ulDataLen) = 0;
        virtual CK_BBOOL IsEmpty();

        CK_BBOOL ToBool();
        CK_ULONG ToNumber();
        Scoped<Buffer> ToBytes();
        std::string ToString();

        template<typename T>
        T* To() {
            T* attr = dynamic_cast<T*>(this);
            if (!attr) {
                THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, "Cannot convert Attribute");
            }
            return attr;
        }
    };

    template<typename T>
    class AttributeTemplate : public Attribute {
    public:
        static void Check(
            CK_VOID_PTR         pData,
            CK_ULONG            ulDataLen
        ) {
        }

        AttributeTemplate(
            CK_ATTRIBUTE_TYPE   type,
            CK_VOID_PTR         pData,
            CK_ULONG            ulDataLen,
            CK_ULONG            flags
        ) :
            Attribute(type, flags),
            value(Scoped<std::vector<T>>(new std::vector<T>))
        {
            try {
                SetValue(pData, ulDataLen);
            }
            CATCH_EXCEPTION
        }

        CK_ULONG Size()
        {
            return value->size();
        }

        void GetValue(CK_VOID_PTR pData, CK_ULONG_PTR pulDataLen)
        {
            try {
                if (pData == NULL) {
                    *pulDataLen = Size();
                }
                else if (*pulDataLen < Size()) {
                    THROW_PKCS11_BUFFER_TOO_SMALL();
                }
                else {
                    memcpy(pData, value->data(), Size());
                    *pulDataLen = Size();
                }
            }
            CATCH_EXCEPTION
        }

        void SetValue(CK_VOID_PTR pData, CK_ULONG ulDataLen)
        {
            try {
                Check(pData, ulDataLen);
                value->resize(ulDataLen);
                memcpy(value->data(), pData, ulDataLen);
            }
            CATCH_EXCEPTION
        }

        CK_BBOOL IsEmpty()
        {
            return value->empty();
        }
    protected:
        Scoped<std::vector<T>> value;
    };

    class AttributeBytes : public AttributeTemplate<CK_BYTE> {
    public:
        static Scoped<AttributeBytes> New(
            CK_ATTRIBUTE_TYPE   type,
            CK_BYTE_PTR         pData,
            CK_ULONG            ulDataLen,
            CK_ULONG            flags
        );

        AttributeBytes(
            CK_ATTRIBUTE_TYPE   type,
            CK_BYTE_PTR         pData,
            CK_ULONG            ulDataLen,
            CK_ULONG            flags
        );

        static void Check(
            CK_BYTE_PTR         pData,
            CK_ULONG            ulDataLen
        );

        void  Set(
            CK_BYTE_PTR pData,
            CK_ULONG    ulDataLen
        );

        Scoped<Buffer> ToValue();
    };

    class AttributeBool : public AttributeBytes {
    public:
        static Scoped<AttributeBool> New(
            CK_ATTRIBUTE_TYPE   type,
            CK_BBOOL            bData,
            CK_ULONG            flags
        );

        static void Check(
            CK_BYTE_PTR         pData,
            CK_ULONG            ulDataLen
        );

        AttributeBool(
            CK_ATTRIBUTE_TYPE   type,
            CK_BBOOL            bData,
            CK_ULONG            flags
        );

        void Set(CK_BBOOL value);

        CK_BBOOL ToValue();
    };

    class AttributeNumber : public AttributeBytes {
    public:
        static Scoped<AttributeNumber> New(
            CK_ATTRIBUTE_TYPE   type,
            CK_ULONG            ulData,
            CK_ULONG            flags
        );

        AttributeNumber(
            CK_ATTRIBUTE_TYPE   type,
            CK_ULONG            ulData,
            CK_ULONG            flags
        );

        static void Check(
            CK_BYTE_PTR         pData,
            CK_ULONG            ulDataLen
        );

        void Set(CK_ULONG value);

        CK_ULONG ToValue();
    };

    class Attributes {
    public:
        Scoped<Attribute> ItemByType(
            CK_ATTRIBUTE_TYPE   type
        );
        Scoped<Attribute> ItemByIndex(
            CK_ULONG        index
        );
        bool HasAttribute(
            CK_ATTRIBUTE_TYPE   type
        );
        CK_ULONG Size();
    protected:
        std::vector<Scoped<Attribute>> items;

        void Add(
            Scoped<Attribute> item
        );
    };

    class AttributeAllowedMechanisms : public AttributeTemplate<CK_MECHANISM_TYPE> {
    public:
        static Scoped<AttributeAllowedMechanisms> New(
            CK_ATTRIBUTE_TYPE       type,
            CK_MECHANISM_TYPE_PTR   pMechanismType,
            CK_ULONG                ulMechanismTypeLen,
            CK_ULONG                flags
        );

        AttributeAllowedMechanisms(
            CK_ATTRIBUTE_TYPE       type,
            CK_MECHANISM_TYPE_PTR   pMechanismType,
            CK_ULONG                ulMechanismTypeLen,
            CK_ULONG                flags
        );
    };

}