#include "ec.h"

using namespace mscapi;

Scoped<CryptoKeyPair> EcKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
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

#define POINT_COMPARE(curve) memcmp(core::EC_##curve##_BLOB, point->data(), strlen(core::EC_##curve##_BLOB)) == 0

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

        // TODO: Random name for key. If TOKEN flag is true
        auto key = provider->GenerateKeyPair(pszAlgorithm, NULL, 0, 0);

        // Key Usage
        ULONG keyUsage = 0;
        if (publicTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
            keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
        }
        if (publicTemplate->GetBool(CKA_DERIVE, false, false)) {
            keyUsage |= NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        }
        key->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, keyUsage);

        // TODO: Extractable
        key->SetNumber(NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_PERSIST_FLAG);

        key->Finalize();

        privateKey->Assign(key);
        publicKey->Assign(key);

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

void EcPrivateKey::FillKeyStruct()
{
    try {
        DWORD dwKeyLen = 0;
        BYTE* pbKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_ECCPRIVATE_BLOB, 0, NULL, 0, &dwKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbKey = (BYTE*)malloc(dwKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_ECCPRIVATE_BLOB, 0, pbKey, dwKeyLen, &dwKeyLen, 0)) {
            free(pbKey);
            THROW_NT_EXCEPTION(status);
        }

        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)pbKey;
        PCHAR pValue = (PCHAR)(pbKey + sizeof(BCRYPT_ECCKEY_BLOB) + (header->cbKey * 2));


        // PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PRIVATE_P256_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P256_BLOB, strlen(core::EC_P256_BLOB));
            break;
        case BCRYPT_ECDH_PRIVATE_P384_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P384_BLOB, strlen(core::EC_P384_BLOB));
            break;
        case BCRYPT_ECDH_PRIVATE_P521_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P521_MAGIC: {
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)&core::EC_P521_BLOB, strlen(core::EC_P521_BLOB));
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }
        // POINT
        ItemByType(CKA_VALUE)->SetValue(pValue, header->cbKey);

        free(pbKey);
    }
    CATCH_EXCEPTION
}

CK_RV EcPrivateKey::GetValue(
    CK_ATTRIBUTE_PTR attr
)
{
    try {
        core::EcPrivateKey::GetValue(attr);

        switch (attr->type) {
        case CKA_EC_PARAMS:
        case CKA_VALUE:
            if (ItemByType(attr->type)->IsEmpty()) {
                FillKeyStruct();
            }
            break;
        }
    }
    CATCH_EXCEPTION
}

CK_RV EcPrivateKey::CreateValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::EcPrivateKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        std::vector<CK_BYTE> buffer;

        buffer.resize(sizeof(BCRYPT_ECCKEY_BLOB));
        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)&buffer[0];

        // Named curve
        auto params = ItemByType(CKA_EC_PARAMS)->To<core::AttributeBytes>()->ToValue();

        if (!memcmp(core::EC_P256_BLOB, params->data(), strlen(core::EC_P256_BLOB))) {
            header->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        }
        else if (!memcmp(core::EC_P384_BLOB, params->data(), strlen(core::EC_P384_BLOB))) {
            header->dwMagic = BCRYPT_ECDSA_PRIVATE_P384_MAGIC;
        }
        else if (!memcmp(core::EC_P521_BLOB, params->data(), strlen(core::EC_P521_BLOB))) {
            header->dwMagic = BCRYPT_ECDSA_PRIVATE_P521_MAGIC;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "Wrong NamedCorve value");
        }

        core::Template tmpl(pTemplate, ulCount);
        BCRYPT_ECCKEY_BLOB blob;

    }
    CATCH_EXCEPTION
}

// Public key

void EcPublicKey::FillKeyStruct()
{
    try {
        DWORD dwKeyLen = 0;
        BYTE* pbKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_ECCPUBLIC_BLOB, 0, NULL, 0, &dwKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbKey = (BYTE*)malloc(dwKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_ECCPUBLIC_BLOB, 0, pbKey, dwKeyLen, &dwKeyLen, 0)) {
            free(pbKey);
            THROW_NT_EXCEPTION(status);
        }

        BCRYPT_ECCKEY_BLOB* header = (BCRYPT_ECCKEY_BLOB*)pbKey;
        PCHAR pPoint = (PCHAR)(pbKey + sizeof(BCRYPT_ECCKEY_BLOB));

        // POINT
        auto propPoint = Scoped<std::string>(new std::string(""));

        // PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, strlen(core::EC_P256_BLOB));
            *propPoint += std::string({ 0x04, 0x41, 0x04 });
            break;
        case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, strlen(core::EC_P384_BLOB));
            *propPoint += std::string({ 0x04, 0x61, 0x04 });
            break;
        case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: {
            ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, strlen(core::EC_P521_BLOB));
            char padding[] = { 0x04, 0x81, 0x85, 0x04 };
            *propPoint += std::string(padding);
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }
        *propPoint += std::string(pPoint, header->cbKey * 2);
        ItemByType(CKA_EC_POINT)->SetValue((CK_VOID_PTR)propPoint->c_str(), propPoint->length());

        free(pbKey);
    }
    CATCH_EXCEPTION;
}

CK_RV EcPublicKey::GetValue(
    CK_ATTRIBUTE_PTR attr
)
{
    try {
        core::EcPublicKey::GetValue(attr);

        switch (attr->type) {
        case CKA_EC_PARAMS:
        case CKA_EC_POINT:
            if (ItemByType(attr->type)->IsEmpty()) {
                FillKeyStruct();
            }
            break;
        }
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> EcKey::DeriveKey(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    baseKey,
    Scoped<core::Template>  tmpl
)
{
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
    try {
        core::Template tmpl(pTemplate, ulCount);
        core::EcPublicKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        Scoped<Buffer> buffer(new Buffer);


        // Named curve
        auto params = ItemByType(CKA_EC_PARAMS)->To<core::AttributeBytes>()->ToValue();

        ULONG dwMagic;
        ULONG keySize;
        if (!memcmp(core::EC_P256_BLOB, params->data(), strlen(core::EC_P256_BLOB))) {
            dwMagic = BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
            keySize = 32;
        }
        else if (!memcmp(core::EC_P384_BLOB, params->data(), strlen(core::EC_P384_BLOB))) {
            dwMagic = BCRYPT_ECDSA_PUBLIC_P384_MAGIC;
            keySize = 48;
        }
        else if (!memcmp(core::EC_P521_BLOB, params->data(), strlen(core::EC_P521_BLOB))) {
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

        ncrypt::Provider provider;
        provider.Open(NULL, 0);

        auto key = provider.ImportKey(BCRYPT_ECCPUBLIC_BLOB, buffer->data(), buffer->size(), 0);
        Assign(key);

    }
    CATCH_EXCEPTION
}