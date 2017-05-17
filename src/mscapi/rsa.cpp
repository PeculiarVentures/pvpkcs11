#include "rsa.h"
#include "helper.h"
#include "ncrypt.h"

using namespace mscapi;

Scoped<CryptoKeyPair> RsaKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        Scoped<RsaPrivateKey> privateKey(new RsaPrivateKey());
        privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());

        Scoped<RsaPublicKey> publicKey(new RsaPublicKey());
        publicKey->GenerateValues(publicTemplate->Get(), publicTemplate->Size());

        NTSTATUS status;
        ULONG modulusLength = publicTemplate->GetNumber(CKA_MODULUS_BITS, true, 0);

        // NCRYPT
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        // TODO: Random name for key. If TOKEN flag is true
        auto key = provider->GenerateKeyPair(NCRYPT_RSA_ALGORITHM, NULL, 0, 0);

        // Public exponent
        auto publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
        char PUBLIC_EXPONENT_65537[3] = { 1,0,1 };
        if (!(publicExponent->length() == 3 && !strncmp(publicExponent->c_str(), PUBLIC_EXPONENT_65537, 3))) {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
        }
        // Modulus length
        key->SetNumber(NCRYPT_LENGTH_PROPERTY, publicTemplate->GetNumber(CKA_MODULUS_BITS, true));
        // Key Usage
        ULONG keyUsage = 0;
        if (publicTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
            keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
        }
        if (publicTemplate->GetBool(CKA_ENCRYPT, false, false) || publicTemplate->GetBool(CKA_DECRYPT, false, false) ||
            publicTemplate->GetBool(CKA_WRAP, false, false) || publicTemplate->GetBool(CKA_UNWRAP, false, false)) {
            keyUsage |= NCRYPT_ALLOW_DECRYPT_FLAG;
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

// RSA private key

void RsaPrivateKey::FillKeyStruct()
{
    try {
        DWORD dwKeyLen = 0;
        BYTE* pbKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAFULLPRIVATE_BLOB, 0, NULL, 0, &dwKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbKey = (BYTE*)malloc(dwKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAFULLPRIVATE_BLOB, 0, pbKey, dwKeyLen, &dwKeyLen, 0)) {
            free(pbKey);
            THROW_NT_EXCEPTION(status);
        }

        // BCRYPT_RSAKEY_BLOB
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbKey;
        // PublicExponent[cbPublicExp]  // Big-endian.
        PBYTE pbPublicExponent = (PBYTE)(pbKey + sizeof(BCRYPT_RSAKEY_BLOB));
        ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(pbPublicExponent, header->cbPublicExp);
        // Modulus[cbModulus]           // Big-endian.
        PBYTE pbModulus = (PBYTE)(pbPublicExponent + header->cbPublicExp);
        ItemByType(CKA_MODULUS)->SetValue(pbModulus, header->cbModulus);
        // Prime1[cbPrime1]             // Big-endian.
        PBYTE pbPrime1 = (PBYTE)(pbModulus + header->cbModulus);
        ItemByType(CKA_PRIME_1)->SetValue(pbPrime1, header->cbPrime1);
        // Prime2[cbPrime2]             // Big-endian.
        PBYTE pbPrime2 = (PBYTE)(pbPrime1 + header->cbPrime1);
        ItemByType(CKA_PRIME_2)->SetValue(pbPrime2, header->cbPrime2);
        // Exponent1[cbPrime1]          // Big-endian.
        PBYTE pbExponent1 = (PBYTE)(pbPrime2 + header->cbPrime2);
        ItemByType(CKA_EXPONENT_1)->SetValue(pbExponent1, header->cbPrime1);
        // Exponent2[cbPrime2]          // Big-endian.
        PBYTE pbExponent2 = (PBYTE)(pbExponent1 + header->cbPrime1);
        ItemByType(CKA_EXPONENT_2)->SetValue(pbExponent2, header->cbPrime2);
        // Coefficient[cbPrime1]        // Big-endian.
        PBYTE pbCoefficient = (PBYTE)(pbExponent2 + header->cbPrime2);
        ItemByType(CKA_COEFFICIENT)->SetValue(pbCoefficient, header->cbPrime1);
        // PrivateExponent[cbModulus]   // Big-endian.
        PBYTE pbPrivateExponent = (PBYTE)(pbCoefficient + header->cbPrime1);
        ItemByType(CKA_PRIVATE_EXPONENT)->SetValue(pbPrivateExponent, header->cbModulus);

        free(pbKey);
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::GetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
        switch (attr->type) {
        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT:
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_PRIVATE_EXPONENT:
        {
            if (ItemByType(attr->type)->IsEmpty()) {
                FillKeyStruct();
            }
            break;
        }
        }
    }
    CATCH_EXCEPTION
}

// RSA public key

void RsaPublicKey::FillKeyStruct()
{
    try {
        DWORD dwKeyLen = 0;
        BYTE* pbKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &dwKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbKey = (BYTE*)malloc(dwKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, pbKey, dwKeyLen, &dwKeyLen, 0)) {
            free(pbKey);
            THROW_NT_EXCEPTION(status);
        }

        // BCRYPT_RSAKEY_BLOB
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbKey;
        // ModulusBits
        ItemByType(CKA_MODULUS_BITS)->To<core::AttributeNumber>()->Set(header->BitLength);
        // PublicExponent[cbPublicExp]  // Big-endian.
        PBYTE pbPublicExponent = (PBYTE)(pbKey + sizeof(BCRYPT_RSAKEY_BLOB));
        ItemByType(CKA_PUBLIC_EXPONENT)->To<core::AttributeBytes>()->Set(pbPublicExponent, header->cbPublicExp);
        // Modulus[cbModulus]           // Big-endian.
        PBYTE pbModulus = (PBYTE)(pbPublicExponent + header->cbPublicExp);
        ItemByType(CKA_MODULUS)->To<core::AttributeBytes>()->Set(pbModulus, header->cbModulus);

        free(pbKey);
    }
    CATCH_EXCEPTION
}

CK_RV RsaPublicKey::GetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    try {
        switch (attr->type) {
        case CKA_MODULUS:
        case CKA_MODULUS_BITS:
        case CKA_PUBLIC_EXPONENT: {
            if (ItemByType(attr->type)->IsEmpty()) {
                FillKeyStruct();
            }
            break;
        }
        }
    }
    CATCH_EXCEPTION
}