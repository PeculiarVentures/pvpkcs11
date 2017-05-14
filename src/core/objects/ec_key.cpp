#include "ec_key.h"

using namespace core;

// Private Key

CK_RV EcPrivateKey::GetAttributeValue
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        CHECK_ARGUMENT_NULL(pTemplate);
        CK_RV res = CKR_OK;

        for (size_t i = 0; i < ulCount && res == CKR_OK; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];

            switch (attr->type) {
            case CKA_ECDSA_PARAMS:
                res = GetParams((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
                break;
            case CKA_VALUE:
                res = GetValue((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
                break;
            default:
                res = PrivateKey::GetAttributeValue(attr, 1);
            }
        }

        return res;
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPrivateKey::GetKeyType)
{
    try {
        return GetNumber(pValue, pulValueLen, CKK_ECDSA);
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPrivateKey::GetParams)
{
    try {
        return GetBytes(pValue, pulValueLen, propParams.get());
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPrivateKey::GetValue)
{
    try {
        if (!propExtractable) {
            return CKR_ATTRIBUTE_SENSITIVE;
        }
        
        GetKeyStruct();

        return GetBytes(pValue, pulValueLen, propValue.get());
    }
    CATCH_EXCEPTION
}

// Public Key

CK_RV EcPublicKey::GetAttributeValue
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        CHECK_ARGUMENT_NULL(pTemplate);
        CK_RV res = CKR_OK;

        for (size_t i = 0; i < ulCount && res == CKR_OK; i++) {
            CK_ATTRIBUTE_PTR attr = &pTemplate[i];

            switch (attr->type) {
            case CKA_ECDSA_PARAMS:
                res = GetParams((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
                break;
            case CKA_EC_POINT:
                res = GetPoint((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
                break;
            default:
                res = PublicKey::GetAttributeValue(attr, 1);
            }
        }

        return res;
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPublicKey::GetParams)
{
    try {
        GetKeyStruct();

        return GetBytes(pValue, pulValueLen, propParams.get());
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPublicKey::GetPoint)
{
    try {
        GetKeyStruct();

        return GetBytes(pValue, pulValueLen, propPoint.get());
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(EcPublicKey::GetKeyType)
{
    try {
        return GetNumber(pValue, pulValueLen, CKK_ECDSA);
    }
    CATCH_EXCEPTION
}