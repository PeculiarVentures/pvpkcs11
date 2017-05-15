#include "rsa_private_key.h"

using namespace core;

CK_RV RsaPrivateKey::GetAttributeValue
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    CHECK_ARGUMENT_NULL(pTemplate);
    CK_RV res = CKR_OK;

    for (size_t i = 0; i < ulCount && res == CKR_OK; i++) {
        CK_ATTRIBUTE_PTR attr = &pTemplate[i];

        switch (attr->type) {
        case CKA_MODULUS:
            res = GetModulus((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_PUBLIC_EXPONENT:
            res = GetPublicExponent((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_PRIVATE_EXPONENT:
            res = GetPrivateExponent((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_PRIME_1:
            res = GetPrime1((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_PRIME_2:
            res = GetPrime2((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_EXPONENT_1:
            res = GetExponent1((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_EXPONENT_2:
            res = GetExponent2((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        case CKA_COEFFICIENT:
            res = GetCoefficient((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
            break;
        default:
            res = PrivateKey::GetAttributeValue(attr, 1);
        }
    }

    return res;
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetModulus)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->n);
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPublicExponent)
{
    Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
    CK_RV res = this->GetKeyStruct(key.get());
    if (res != CKR_OK) {
        return res;
    }

    return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->n.c_str(), key->n.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrivateExponent)
{
    try {
        // TODO: Move checking for Private functionality to Method
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->d.c_str(), key->d.length());
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrime1)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->p);
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrime2)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->q);
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetExponent1)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->dp);
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetExponent2)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->dq);
        }
    }
    CATCH_EXCEPTION
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetCoefficient)
{
    try {
        if (propExtractable && propSensitive) {
            Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
            CK_RV res = this->GetKeyStruct(key.get());
            if (res != CKR_OK) {
                return res;
            }

            return this->GetBytes(pValue, pulValueLen, &key->qi);
        }
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::GetKeyStruct(RsaPrivateKeyStruct* rsaKey)
{
    return CKR_FUNCTION_NOT_SUPPORTED;
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetKeyType)
{
    return this->GetNumber(pValue, pulValueLen, CKK_RSA);
}