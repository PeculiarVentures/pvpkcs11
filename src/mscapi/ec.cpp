#include "ec.h"

using namespace mscapi;

Scoped<CryptoKeyPair> EcKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
    try {
        NTSTATUS status;
        Scoped<std::string> point = publicTemplate->GetBytes(CKA_EC_PARAMS, true, "");

        LPCWSTR pszAlgorithm;
        if (strcmp(core::EC_P256_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P256_ALGORITHM;
        }
        else if (strcmp(core::EC_P384_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P384_ALGORITHM;
        }
        else if (strcmp(core::EC_P384_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P521_ALGORITHM;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Wrong POINT for EC key");
        }

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

        Scoped<core::PrivateKey> privateKey(new EcPrivateKey(key));
        privateKey->propId = *privateTemplate->GetBytes(CKA_ID, false, "");
        privateKey->propExtractable = privateTemplate->GetBool(CKA_EXTRACTABLE, false, false);
        privateKey->propSign = privateTemplate->GetBool(CKA_SIGN, false, false);
        privateKey->propDerive = privateTemplate->GetBool(CKA_DERIVE, false, false);

        Scoped<core::PublicKey> publicKey(new EcPublicKey(key));
        publicKey->propId = *publicTemplate->GetBytes(CKA_ID, false, "");
        publicKey->propVerify = privateTemplate->GetBool(CKA_VERIFY, false, false);
        publicKey->propDerive = privateTemplate->GetBool(CKA_DERIVE, false, false);

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

void EcPrivateKey::GetKeyStruct()
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

        // POINT
        propValue = Scoped<std::string>(new std::string(""));

        // PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PRIVATE_P256_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P256_MAGIC:
            propParams = Scoped<std::string>(new std::string(core::EC_P256_BLOB));
            break;
        case BCRYPT_ECDH_PRIVATE_P384_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P384_MAGIC:
            propParams = Scoped<std::string>(new std::string(core::EC_P384_BLOB));
            break;
        case BCRYPT_ECDH_PRIVATE_P521_MAGIC:
        case BCRYPT_ECDSA_PRIVATE_P521_MAGIC: {
            propParams = Scoped<std::string>(new std::string(core::EC_P521_BLOB));
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }
        *propValue += std::string(pValue, header->cbKey);

        free(pbKey);
    }
    CATCH_EXCEPTION
}

void EcPublicKey::GetKeyStruct()
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
        propPoint = Scoped<std::string>(new std::string(""));

        // PARAM
        switch (header->dwMagic) {
        case BCRYPT_ECDH_PUBLIC_P256_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P256_MAGIC:
            propParams = Scoped<std::string>(new std::string(core::EC_P256_BLOB));
            *propPoint += std::string({ 0x04, 0x41, 0x04 });
            break;
        case BCRYPT_ECDH_PUBLIC_P384_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P384_MAGIC:
            propParams = Scoped<std::string>(new std::string(core::EC_P384_BLOB));
            *propPoint += std::string({ 0x04, 0x61, 0x04 });
            break;
        case BCRYPT_ECDH_PUBLIC_P521_MAGIC:
        case BCRYPT_ECDSA_PUBLIC_P521_MAGIC: {
            propParams = Scoped<std::string>(new std::string(core::EC_P521_BLOB));
            char padding[] = { 0x04, 0x81, 0x85, 0x04 };
            *propPoint += std::string(padding);
            break;
        }
        default:
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Unsupported named curve");
        }
        *propPoint += std::string(pPoint, header->cbKey * 2);

        free(pbKey);
    }
    CATCH_EXCEPTION;
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