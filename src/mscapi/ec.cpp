#include "ec.h"

#include "ncrypt/provider.h"
#include "ncrypt/key.h"

using namespace mscapi;

Scoped<CryptoKeyPair> EcKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        NTSTATUS status;
        auto point = publicTemplate->GetBytes(CKA_EC_PARAMS, true, "");

        Scoped<EcPrivateKey> privateKey(new EcPrivateKey());
        privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());

        Scoped<EcPublicKey> publicKey(new EcPublicKey());
        publicKey->GenerateValues(publicTemplate->Get(), publicTemplate->Size());

        LPCWSTR pszAlgorithm;

#define POINT_COMPARE(curve) memcmp(core::EC_##curve##_BLOB, point->data(), sizeof(core::EC_##curve##_BLOB)-1 ) == 0

        if (POINT_COMPARE(P256)) {
            pszAlgorithm = NCRYPT_ECDSA_P256_ALGORITHM;
        }
        else if (POINT_COMPARE(P384)) {
            pszAlgorithm = NCRYPT_ECDSA_P384_ALGORITHM;
        }
        else if (POINT_COMPARE(P521)) {
            pszAlgorithm = NCRYPT_ECDSA_P521_ALGORITHM;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Wrong POINT for EC key");
        }

#undef POINT_COMPARE

        // NCRYPT
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        Scoped<ncrypt::Key> nKey;
        if (!privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue()) {
            nKey = provider->CreatePersistedKey(pszAlgorithm, NULL, 0, 0);
        }
        else {
            nKey = provider->CreatePersistedKey(pszAlgorithm, provider->GenerateRandomName()->c_str(), 0, 0);
        }

        // Key Usage
        ULONG keyUsage = 0;
        if (publicTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
            keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
        }
        if (publicTemplate->GetBool(CKA_DERIVE, false, false)) {
            keyUsage |= NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        }
        nKey->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, keyUsage);

        auto attrToken = privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue();
        auto attrExtractable = privateKey->ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->ToValue();
        if ((attrToken && attrExtractable) || !attrToken) {
            // Make all session keys extractable. It allows to copy keys from session to storage via export/import
            // This is extractable only for internal usage. Key object will have CKA_EXTRACTABLE with setted value
            nKey->SetNumber(NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_PERSIST_FLAG);
        }

        nKey->Finalize();

        Scoped<CryptoKey> cryptoKey(new CryptoKey(nKey));

        privateKey->SetKey(cryptoKey);
        publicKey->SetKey(cryptoKey);

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

void EcPrivateKey::FillPublicKeyStruct()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        auto nkey = GetKey()->GetNKey();
        auto buffer = nkey->Export(BCRYPT_ECCPUBLIC_BLOB);
        PUCHAR pbKey = buffer->data();
        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)pbKey;

        // CKA_PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P256_BLOB, 10);
            break;
        case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P384_BLOB, 7);
            break;
        case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: {
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P521_BLOB, 7);
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }

        DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        // NCRYPT_KEY_USAGE_PROPERTY can contain zero or a combination of one or more of the values
        try {
            keyUsage = nkey->GetNumber(NCRYPT_KEY_USAGE_PROPERTY);
        }
        catch (...) {
            // Cannot get NCRYPT_KEY_USAGE_PROPERTY
        }
        if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
            ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(true);
        }
        if (keyUsage & NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) {
            ItemByType(CKA_DERIVE)->To<core::AttributeBool>()->Set(true);
        }

    }
    CATCH_EXCEPTION
}

void EcPrivateKey::FillPrivateKeyStruct()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        auto nkey = GetKey()->GetNKey();
        auto buffer = nkey->Export(BCRYPT_ECCPUBLIC_BLOB, 0);
        PUCHAR pbKey = buffer->data();
        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)pbKey;
        PCHAR pValue = (PCHAR)(pbKey + sizeof(BCRYPT_ECCKEY_BLOB) + (header->cbKey * 2));

        // CK_VALUE
        ItemByType(CKA_VALUE)->SetValue(pValue, header->cbKey);
    }
    CATCH_EXCEPTION
}

CK_RV EcPrivateKey::GetValue(
    CK_ATTRIBUTE_PTR attr
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::EcPrivateKey::GetValue(attr);

        switch (attr->type) {
        case CKA_SIGN:
        case CKA_DERIVE:
        case CKA_EC_PARAMS:
            if (ItemByType(CKA_EC_PARAMS)->IsEmpty()) {
                FillPublicKeyStruct();
            }
            break;
        case CKA_VALUE:
            if (ItemByType(attr->type)->IsEmpty()) {
                FillPrivateKeyStruct();
            }
            break;
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV EcPrivateKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::EcPrivateKey::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        EcPrivateKey* originalKey = dynamic_cast<EcPrivateKey*>(object.get());
        if (!originalKey) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Original key must be EcPrivateKey");
        }

        ncrypt::Provider provider;
        provider.Open(wstrProvName.c_str(), 0);

        auto attrToken = ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue();
        auto attrExtractable = ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->ToValue();
        
        std::wstring wstrContainerName = L"";
        if (wstrScope.length()) {
            wstrContainerName += wstrScope + provider.GenerateRandomName()->c_str();
        }
        else {
            wstrContainerName = provider.GenerateRandomName()->c_str();
        }

        auto nkey = provider.SetKey(
            originalKey->GetKey()->GetNKey(),
            BCRYPT_ECCPRIVATE_BLOB,
            attrToken ? wstrContainerName.c_str() : NULL,
            (attrToken && attrExtractable) || !attrToken
        );
        
        SetKey(Scoped<CryptoKey>(new CryptoKey(nkey)));

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::EcPrivateKey::Destroy()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        GetKey()->GetNKey()->Delete(0);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

// Public key

void EcPublicKey::FillKeyStruct()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        auto nkey = GetKey()->GetNKey();
        auto buffer = nkey->Export(BCRYPT_ECCPUBLIC_BLOB, 0);
        PUCHAR pbKey = buffer->data();
        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)pbKey;
        PCHAR pPoint = (PCHAR)(pbKey + sizeof(BCRYPT_ECCKEY_BLOB));

        // POINT
        auto propPoint = Scoped<std::string>(new std::string(""));

        // PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, 10);
            *propPoint += std::string("\x04\x41\x04");
            break;
        case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, 7);
            *propPoint += std::string("\x04\x61\x04");
            break;
        case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: {
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, 7);
            *propPoint += std::string("\x04\x81\x85\x04");
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }
        *propPoint += std::string(pPoint, header->cbKey * 2);
        ItemByType(CKA_EC_POINT)->SetValue((CK_VOID_PTR)propPoint->c_str(), propPoint->length());

        auto keyUsage = nkey->GetNumber(NCRYPT_KEY_USAGE_PROPERTY);
        if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
            ItemByType(CKA_VERIFY)->To<core::AttributeBool>()->Set(true);
        }
        if (keyUsage & NCRYPT_ALLOW_KEY_AGREEMENT_FLAG) {
            ItemByType(CKA_DERIVE)->To<core::AttributeBool>()->Set(true);
        }

    }
    CATCH_EXCEPTION;
}

CK_RV EcPublicKey::GetValue(
    CK_ATTRIBUTE_PTR attr
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::EcPublicKey::GetValue(attr);

        switch (attr->type) {
        case CKA_VERIFY:
        case CKA_DERIVE:
        case CKA_EC_PARAMS:
        case CKA_EC_POINT:
            if (ItemByType(CKA_EC_POINT)->IsEmpty()) {
                FillKeyStruct();
            }
            break;
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> EcKey::DeriveKey(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    baseKey,
    Scoped<core::Template>  tmpl
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        EcPrivateKey* ecPrivateKey = dynamic_cast<EcPrivateKey*>(baseKey.get());
        if (!ecPrivateKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "baseKey is not EC key");
        }

        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_ECDH1_DERIVE) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism->mechanism is not CKM_ECDH1_DERIVE");
        }
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }
        CK_ECDH1_DERIVE_PARAMS_PTR params = static_cast<CK_ECDH1_DERIVE_PARAMS_PTR>(pMechanism->pParameter);
        if (!params) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is not CK_ECDH1_DERIVE_PARAMS");
        }

        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

CK_RV EcPublicKey::CreateValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::Template tmpl(pTemplate, ulCount);
        core::EcPublicKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        Scoped<Buffer> buffer(new Buffer);


        // Named curve
        auto params = ItemByType(CKA_EC_PARAMS)->To<core::AttributeBytes>()->ToValue();

        ULONG dwMagic;
        ULONG keySize;
        if (!memcmp(core::EC_P256_BLOB, params->data(), sizeof(core::EC_P256_BLOB) - 1)) {
            dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            keySize = 32;
        }
        else if (!memcmp(core::EC_P384_BLOB, params->data(), sizeof(core::EC_P384_BLOB) - 1)) {
            dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
            keySize = 48;
        }
        else if (!memcmp(core::EC_P521_BLOB, params->data(), sizeof(core::EC_P521_BLOB) - 1)) {
            dwMagic = BCRYPT_ECDSA_PUBLIC_P521_MAGIC;
            keySize = 66;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "Wrong NamedCorve value");
        }

        auto tmplPoint = tmpl.GetBytes(CKA_EC_POINT, true, "");
        auto decodedPoint = core::EcUtils::DecodePoint(tmplPoint, keySize);

        buffer->resize(sizeof(BCRYPT_ECCKEY_BLOB));
        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)buffer->data();
        header->dwMagic = dwMagic;
        header->cbKey = keySize;
        buffer->insert(buffer->end(), decodedPoint->X->begin(), decodedPoint->X->end());
        buffer->insert(buffer->end(), decodedPoint->Y->begin(), decodedPoint->Y->end());

        Scoped<ncrypt::Key> nKey(new ncrypt::Key);
        nKey->Import(BCRYPT_ECCPUBLIC_BLOB, buffer);
        
        SetKey(nKey);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV EcPublicKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::EcPublicKey::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        EcPublicKey* originalKey = dynamic_cast<EcPublicKey*>(object.get());
        if (!originalKey) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Original key must be EcPrivateKey");
        }

        // It'll not be added to storage. Because mscapi slot creates 2 keys (private/public) from 1 key container

        SetKey(originalKey->GetKey());

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::EcPublicKey::Destroy()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}
