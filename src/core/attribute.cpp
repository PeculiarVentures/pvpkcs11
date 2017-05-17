#include "attribute.h"

using namespace core;

struct AttributeInfo {
    CK_ATTRIBUTE_TYPE   type;
    const char*         name;
    CK_ULONG            dataType;
};

// Attribute data types
#define PVT_ATTRIBUTE_VOID              0
#define PVT_ATTRIBUTE_BBOOL             1
#define PVT_ATTRIBUTE_ULONG             2
#define PVT_ATTRIBUTE_BYTES             3
#define PVT_ATTRIBUTE_UTF8_STRING       4

std::vector<AttributeInfo> attr_info({
    { CKA_CLASS, "CKA_CLASS", PVT_ATTRIBUTE_ULONG },
    { CKA_TOKEN, "CKA_TOKEN", PVT_ATTRIBUTE_BBOOL },
    { CKA_PRIVATE, "CKA_PRIVATE", PVT_ATTRIBUTE_BBOOL },
    { CKA_LABEL, "CKA_LABEL", PVT_ATTRIBUTE_UTF8_STRING },
    { CKA_APPLICATION, "CKA_APPLICATION", PVT_ATTRIBUTE_UTF8_STRING },
    { CKA_VALUE, "CKA_VALUE", PVT_ATTRIBUTE_BYTES },
    { CKA_OBJECT_ID, "CKA_OBJECT_ID", PVT_ATTRIBUTE_BYTES },
    { CKA_CERTIFICATE_TYPE, "CKA_CERTIFICATE_TYPE", PVT_ATTRIBUTE_ULONG },
    { CKA_ISSUER, "CKA_ISSUER", PVT_ATTRIBUTE_BYTES },
    { CKA_SERIAL_NUMBER, "CKA_SERIAL_NUMBER", PVT_ATTRIBUTE_BYTES },
    { CKA_AC_ISSUER, "CKA_AC_ISSUER", PVT_ATTRIBUTE_BYTES },
    { CKA_OWNER, "CKA_OWNER", PVT_ATTRIBUTE_BYTES },
    { CKA_ATTR_TYPES, "CKA_ATTR_TYPES", PVT_ATTRIBUTE_BYTES },
    { CKA_TRUSTED, "CKA_TRUSTED", PVT_ATTRIBUTE_BBOOL },
    { CKA_CERTIFICATE_CATEGORY, "CKA_CERTIFICATE_CATEGORY", PVT_ATTRIBUTE_BYTES },
    { CKA_JAVA_MIDP_SECURITY_DOMAIN, "CKA_JAVA_MIDP_SECURITY_DOMAIN", PVT_ATTRIBUTE_BYTES },
    { CKA_URL, "CKA_URL", PVT_ATTRIBUTE_BYTES },
    { CKA_HASH_OF_SUBJECT_PUBLIC_KEY, "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", PVT_ATTRIBUTE_BYTES },
    { CKA_HASH_OF_ISSUER_PUBLIC_KEY, "CKA_HASH_OF_ISSUER_PUBLIC_KEY", PVT_ATTRIBUTE_BYTES },
    { CKA_NAME_HASH_ALGORITHM, "CKA_NAME_HASH_ALGORITHM", PVT_ATTRIBUTE_BYTES },
    { CKA_CHECK_VALUE, "CKA_CHECK_VALUE", PVT_ATTRIBUTE_BYTES },
    { CKA_KEY_TYPE, "CKA_KEY_TYPE", PVT_ATTRIBUTE_ULONG },
    { CKA_SUBJECT, "CKA_SUBJECT", PVT_ATTRIBUTE_BYTES },
    { CKA_ID, "CKA_ID", PVT_ATTRIBUTE_BYTES },
    { CKA_SENSITIVE, "CKA_SENSITIVE", PVT_ATTRIBUTE_BBOOL },
    { CKA_ENCRYPT, "CKA_ENCRYPT", PVT_ATTRIBUTE_BBOOL },
    { CKA_DECRYPT, "CKA_DECRYPT", PVT_ATTRIBUTE_BBOOL },
    { CKA_WRAP, "CKA_WRAP", PVT_ATTRIBUTE_BBOOL },
    { CKA_UNWRAP, "CKA_UNWRAP", PVT_ATTRIBUTE_BBOOL },
    { CKA_SIGN, "CKA_SIGN", PVT_ATTRIBUTE_BBOOL },
    { CKA_SIGN_RECOVER, "CKA_SIGN_RECOVER", PVT_ATTRIBUTE_BBOOL },
    { CKA_VERIFY, "CKA_VERIFY", PVT_ATTRIBUTE_BBOOL },
    { CKA_VERIFY_RECOVER, "CKA_VERIFY_RECOVER", PVT_ATTRIBUTE_BBOOL },
    { CKA_DERIVE, "CKA_DERIVE", PVT_ATTRIBUTE_BBOOL },
    { CKA_START_DATE, "CKA_START_DATE", PVT_ATTRIBUTE_BYTES },
    { CKA_END_DATE, "CKA_END_DATE", PVT_ATTRIBUTE_BYTES },
    { CKA_MODULUS, "CKA_MODULUS", PVT_ATTRIBUTE_BYTES },
    { CKA_MODULUS_BITS, "CKA_MODULUS_BITS", PVT_ATTRIBUTE_BYTES },
    { CKA_PUBLIC_EXPONENT, "CKA_PUBLIC_EXPONENT", PVT_ATTRIBUTE_BYTES },
    { CKA_PRIVATE_EXPONENT, "CKA_PRIVATE_EXPONENT", PVT_ATTRIBUTE_BYTES },
    { CKA_PRIME_1, "CKA_PRIME_1", PVT_ATTRIBUTE_BYTES },
    { CKA_PRIME_2, "CKA_PRIME_2", PVT_ATTRIBUTE_BYTES },
    { CKA_EXPONENT_1, "CKA_EXPONENT_1", PVT_ATTRIBUTE_BYTES },
    { CKA_EXPONENT_2, "CKA_EXPONENT_2", PVT_ATTRIBUTE_BYTES },
    { CKA_COEFFICIENT, "CKA_COEFFICIENT", PVT_ATTRIBUTE_BYTES },
    { CKA_PRIME, "CKA_PRIME", PVT_ATTRIBUTE_BYTES },
    { CKA_SUBPRIME, "CKA_SUBPRIME", PVT_ATTRIBUTE_BYTES },
    { CKA_BASE, "CKA_BASE", PVT_ATTRIBUTE_BYTES },
    { CKA_PRIME_BITS, "CKA_PRIME_BITS", PVT_ATTRIBUTE_BYTES },
    { CKA_SUBPRIME_BITS, "CKA_SUBPRIME_BITS", PVT_ATTRIBUTE_BYTES },
    { CKA_VALUE_BITS, "CKA_VALUE_BITS", PVT_ATTRIBUTE_BYTES },
    { CKA_VALUE_LEN, "CKA_VALUE_LEN", PVT_ATTRIBUTE_ULONG },
    { CKA_EXTRACTABLE, "CKA_EXTRACTABLE", PVT_ATTRIBUTE_BBOOL },
    { CKA_LOCAL, "CKA_LOCAL", PVT_ATTRIBUTE_BBOOL },
    { CKA_NEVER_EXTRACTABLE, "CKA_NEVER_EXTRACTABLE", PVT_ATTRIBUTE_BBOOL },
    { CKA_ALWAYS_SENSITIVE, "CKA_ALWAYS_SENSITIVE", PVT_ATTRIBUTE_BBOOL },
    { CKA_KEY_GEN_MECHANISM, "CKA_KEY_GEN_MECHANISM", PVT_ATTRIBUTE_ULONG },
    { CKA_MODIFIABLE, "CKA_MODIFIABLE", PVT_ATTRIBUTE_BBOOL },
    { CKA_COPYABLE, "CKA_COPYABLE", PVT_ATTRIBUTE_BBOOL },
    { CKA_ECDSA_PARAMS, "CKA_ECDSA_PARAMS", PVT_ATTRIBUTE_BYTES },
    { CKA_EC_PARAMS, "CKA_EC_PARAMS", PVT_ATTRIBUTE_BYTES },
    { CKA_EC_POINT, "CKA_EC_POINT", PVT_ATTRIBUTE_BYTES },
    { CKA_SECONDARY_AUTH, "CKA_SECONDARY_AUTH", PVT_ATTRIBUTE_BYTES },
    { CKA_AUTH_PIN_FLAGS, "CKA_AUTH_PIN_FLAGS", PVT_ATTRIBUTE_BYTES },
    { CKA_ALWAYS_AUTHENTICATE, "CKA_ALWAYS_AUTHENTICATE", PVT_ATTRIBUTE_BYTES },
    { CKA_WRAP_WITH_TRUSTED, "CKA_WRAP_WITH_TRUSTED", PVT_ATTRIBUTE_BYTES },
    { CKA_WRAP_TEMPLATE, "CKA_WRAP_TEMPLATE", PVT_ATTRIBUTE_BYTES },
    { CKA_UNWRAP_TEMPLATE, "CKA_UNWRAP_TEMPLATE", PVT_ATTRIBUTE_BYTES },
    { CKA_DERIVE_TEMPLATE, "CKA_DERIVE_TEMPLATE", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_FORMAT, "CKA_OTP_FORMAT", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_LENGTH, "CKA_OTP_LENGTH", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_TIME_INTERVAL, "CKA_OTP_TIME_INTERVAL", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_USER_FRIENDLY_MODE, "CKA_OTP_USER_FRIENDLY_MODE", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_CHALLENGE_REQUIREMENT, "CKA_OTP_CHALLENGE_REQUIREMENT", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_TIME_REQUIREMENT, "CKA_OTP_TIME_REQUIREMENT", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_COUNTER_REQUIREMENT, "CKA_OTP_COUNTER_REQUIREMENT", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_PIN_REQUIREMENT, "CKA_OTP_PIN_REQUIREMENT", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_COUNTER, "CKA_OTP_COUNTER", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_TIME, "CKA_OTP_TIME", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_USER_IDENTIFIER, "CKA_OTP_USER_IDENTIFIER", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_SERVICE_IDENTIFIER, "CKA_OTP_SERVICE_IDENTIFIER", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_SERVICE_LOGO, "CKA_OTP_SERVICE_LOGO", PVT_ATTRIBUTE_BYTES },
    { CKA_OTP_SERVICE_LOGO_TYPE, "CKA_OTP_SERVICE_LOGO_TYPE", PVT_ATTRIBUTE_BYTES },
    { CKA_GOSTR3410_PARAMS, "CKA_GOSTR3410_PARAMS", PVT_ATTRIBUTE_BYTES },
    { CKA_GOSTR3411_PARAMS, "CKA_GOSTR3411_PARAMS", PVT_ATTRIBUTE_BYTES },
    { CKA_GOST28147_PARAMS, "CKA_GOST28147_PARAMS", PVT_ATTRIBUTE_BYTES },
    { CKA_HW_FEATURE_TYPE, "CKA_HW_FEATURE_TYPE", PVT_ATTRIBUTE_BYTES },
    { CKA_RESET_ON_INIT, "CKA_RESET_ON_INIT", PVT_ATTRIBUTE_BYTES },
    { CKA_HAS_RESET, "CKA_HAS_RESET", PVT_ATTRIBUTE_BYTES },
    { CKA_PIXEL_X, "CKA_PIXEL_X", PVT_ATTRIBUTE_BYTES },
    { CKA_PIXEL_Y, "CKA_PIXEL_Y", PVT_ATTRIBUTE_BYTES },
    { CKA_RESOLUTION, "CKA_RESOLUTION", PVT_ATTRIBUTE_BYTES },
    { CKA_CHAR_ROWS, "CKA_CHAR_ROWS", PVT_ATTRIBUTE_BYTES },
    { CKA_CHAR_COLUMNS, "CKA_CHAR_COLUMNS", PVT_ATTRIBUTE_BYTES },
    { CKA_COLOR, "CKA_COLOR", PVT_ATTRIBUTE_BYTES },
    { CKA_BITS_PER_PIXEL, "CKA_BITS_PER_PIXEL", PVT_ATTRIBUTE_BYTES },
    { CKA_CHAR_SETS, "CKA_CHAR_SETS", PVT_ATTRIBUTE_BYTES },
    { CKA_ENCODING_METHODS, "CKA_ENCODING_METHODS", PVT_ATTRIBUTE_BYTES },
    { CKA_MIME_TYPES, "CKA_MIME_TYPES", PVT_ATTRIBUTE_BYTES },
    { CKA_MECHANISM_TYPE, "CKA_MECHANISM_TYPE", PVT_ATTRIBUTE_BYTES },
    { CKA_REQUIRED_CMS_ATTRIBUTES, "CKA_REQUIRED_CMS_ATTRIBUTES", PVT_ATTRIBUTE_BYTES },
    { CKA_DEFAULT_CMS_ATTRIBUTES, "CKA_DEFAULT_CMS_ATTRIBUTES", PVT_ATTRIBUTE_BYTES },
    { CKA_SUPPORTED_CMS_ATTRIBUTES, "CKA_SUPPORTED_CMS_ATTRIBUTES", PVT_ATTRIBUTE_BYTES },
    { CKA_ALLOWED_MECHANISMS, "CKA_ALLOWED_MECHANISMS", PVT_ATTRIBUTE_BYTES },
});

std::string GetAttributeName(
    CK_ATTRIBUTE_TYPE   type
)
{
    for (CK_ULONG i = 0; i < attr_info.size(); i++) {
        auto item = &attr_info[i];
        if (item->type == type) {
            return std::string(item->name);
        }
    }
    return std::string("UNKNOWN");
}

CK_BBOOL Attribute::IsEmpty()
{
    try {
        CK_ULONG ulDataLen;
        GetValue(NULL, &ulDataLen);

        return !ulDataLen;
    }
    CATCH_EXCEPTION
}

CK_BBOOL Attribute::ToBool()
{
    try {
        To<AttributeBool>()->ToValue();
    }
    CATCH_EXCEPTION;
}

CK_ULONG Attribute::ToNumber()
{
    try {
        To<AttributeNumber>()->ToValue();
    }
    CATCH_EXCEPTION;
}

std::vector<CK_BYTE> Attribute::ToBytes()
{
    try {
        To<AttributeBytes>()->ToValue();
    }
    CATCH_EXCEPTION;
}

std::string Attribute::ToString()
{
    try {
        auto bytes = To<AttributeBytes>()->ToValue();
        return std::string((char*)&bytes[0], bytes.size());
    }
    CATCH_EXCEPTION;
}

AttributeBytes::AttributeBytes(
    CK_ATTRIBUTE_TYPE   type,
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen,
    CK_ULONG            flags
) :
    AttributeTemplate(type, pData, ulDataLen, flags)
{
}

Scoped<AttributeBytes> AttributeBytes::New(
    CK_ATTRIBUTE_TYPE   type,
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen,
    CK_ULONG            flags
)
{
    return Scoped<AttributeBytes>(new AttributeBytes(
        type,
        pData,
        ulDataLen,
        flags
    ));
}

void AttributeBytes::Check(
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen
)
{
    if (pData == NULL) {
        THROW_PKCS11_ATTRIBUTE_VALUE_INVALID();
    }
}

void AttributeBytes::Set(
    CK_BYTE_PTR pData,
    CK_ULONG    ulDataLen
)
{
    try {
        SetValue(pData, ulDataLen);
    }
    CATCH_EXCEPTION
}

std::vector<CK_BYTE> AttributeBytes::ToValue()
{
    return value;
}

AttributeBool::AttributeBool(
    CK_ATTRIBUTE_TYPE   type,
    CK_BBOOL            bData,
    CK_ULONG            flags
) :
    AttributeBytes(type, &bData, sizeof(CK_BBOOL), flags)
{
}

Scoped<AttributeBool> AttributeBool::New(
    CK_ATTRIBUTE_TYPE   type,
    CK_BBOOL            bData,
    CK_ULONG            flags
)
{
    return Scoped<AttributeBool>(new AttributeBool(
        type,
        bData,
        flags
    ));
}

void AttributeBool::Check(
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen
)
{
    if (pData == NULL || sizeof(CK_BBOOL) != ulDataLen) {
        THROW_PKCS11_ATTRIBUTE_VALUE_INVALID();
    }
}

void AttributeBool::Set(
    CK_BBOOL value
)
{
    try {
        SetValue(&value, sizeof(CK_BBOOL));
    }
    CATCH_EXCEPTION
}

CK_BBOOL AttributeBool::ToValue()
{
    CK_BBOOL res;
    if (Size() != sizeof(CK_BBOOL)) {
        THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, "Wrong size of stored data");
    }
    memcpy(&res, value.data(), Size());
    return res;
}

AttributeNumber::AttributeNumber(
    CK_ATTRIBUTE_TYPE   type,
    CK_ULONG            ulData,
    CK_ULONG            flags
) :
    AttributeBytes(type, (CK_BYTE_PTR)&ulData, sizeof(CK_ULONG), flags)
{
}

Scoped<AttributeNumber> AttributeNumber::New(
    CK_ATTRIBUTE_TYPE   type,
    CK_ULONG            ulData,
    CK_ULONG            flags
)
{
    return Scoped<AttributeNumber>(new AttributeNumber(
        type,
        ulData,
        flags
    ));
}

void AttributeNumber::Check(
    CK_BYTE_PTR         pData,
    CK_ULONG            ulDataLen
)
{
    if (pData == NULL || sizeof(CK_ULONG) != ulDataLen) {
        THROW_PKCS11_ATTRIBUTE_VALUE_INVALID();
    }
}

CK_ULONG AttributeNumber::ToValue()
{
    CK_ULONG res;
    if (Size() != sizeof(CK_ULONG)) {
        THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, "Wrong size of stored data");
    }
    memcpy(&res, value.data(), Size());
    return res;
}

void AttributeNumber::Set(
    CK_ULONG value
)
{
    try {
        SetValue(&value, sizeof(CK_ULONG));
    }
    CATCH_EXCEPTION
}

Scoped<Attribute> Attributes::ItemByType(
    CK_ATTRIBUTE_TYPE   type
)
{
    for (CK_ULONG i = 0; i < Size(); i++) {
        auto item = ItemByIndex(i);
        if (item->type == type) {
            return item;
        }
    }
    // Throw error
    std::string message("");
    message += "Cannot get attribute " + GetAttributeName(type);
    THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, message.c_str());
}

Scoped<Attribute> Attributes::ItemByIndex(
    CK_ULONG        index
)
{
    return items[index];
}

bool Attributes::HasAttribute(
    CK_ATTRIBUTE_TYPE   type
)
{
    for (CK_ULONG i = 0; i < Size(); i++) {
        auto item = ItemByIndex(i);
        if (item->type == type) {
            return true;
        }
    }
    return false;
}

CK_ULONG Attributes::Size()
{
    return items.size();
}

void Attributes::Add(
    Scoped<Attribute> item
)
{
    if (HasAttribute(item->type)) {
        std::string message("");
        message += "Attribute " + GetAttributeName(item->type) + " already exists in collection";
        THROW_PKCS11_EXCEPTION(CKR_GENERAL_ERROR, message.c_str());
    }
    items.push_back(item);
}

Scoped<AttributeAllowedMechanisms> AttributeAllowedMechanisms::New(
    CK_ATTRIBUTE_TYPE       type,
    CK_MECHANISM_TYPE_PTR   pMechanismType,
    CK_ULONG                ulMechanismTypeLen,
    CK_ULONG                flags
)
{
    return Scoped<AttributeAllowedMechanisms>(new AttributeAllowedMechanisms(
        type,
        pMechanismType,
        ulMechanismTypeLen,
        flags
    ));
}

AttributeAllowedMechanisms::AttributeAllowedMechanisms(
    CK_ATTRIBUTE_TYPE       type,
    CK_MECHANISM_TYPE_PTR   pMechanismType,
    CK_ULONG                ulMechanismTypeLen,
    CK_ULONG                flags
) :
    AttributeTemplate(type, pMechanismType, ulMechanismTypeLen, flags)
{
}