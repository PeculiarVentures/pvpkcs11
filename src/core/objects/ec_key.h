#pragma once

#include "../../stdafx.h"
#include "../excep.h"
#include "private_key.h"
#include "public_key.h"

namespace core {

    static const char EC_P192_BLOB[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
    static const char EC_P256_BLOB[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const char EC_P384_BLOB[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    static const char EC_P521_BLOB[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

    class EcPrivateKey : public PrivateKey {
    public:
        CK_RV GetAttributeValue
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual DECLARE_GET_ATTRIBUTE(GetParams);
        virtual DECLARE_GET_ATTRIBUTE(GetValue);

        DECLARE_GET_ATTRIBUTE(GetKeyType);

        virtual void GetKeyStruct() = 0;
    
    protected:
        Scoped<std::string> propParams;
        Scoped<std::string> propValue;
    };

    class EcPublicKey : public PublicKey {
    public:
        CK_RV GetAttributeValue
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
            CK_ULONG          ulCount     /* attributes in template */
        );

        DECLARE_GET_ATTRIBUTE(GetKeyType);

        virtual DECLARE_GET_ATTRIBUTE(GetParams);
        virtual DECLARE_GET_ATTRIBUTE(GetPoint);

        virtual void GetKeyStruct() = 0;

    protected:
        Scoped<std::string> propParams;
        Scoped<std::string> propPoint;
    };

}