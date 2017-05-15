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

        Scoped<core::PrivateKey> privateKey(new RsaPrivateKey(key));
        privateKey->propId = *privateTemplate->GetBytes(CKA_ID, false, "");
        privateKey->propSign = privateTemplate->GetBool(CKA_SIGN, false, false);
        privateKey->propDecrypt = privateTemplate->GetBool(CKA_DECRYPT, false, false);
        privateKey->propExtractable = privateTemplate->GetBool(CKA_EXTRACTABLE, false, false);

        Scoped<core::PublicKey> publicKey(new RsaPublicKey(key));
        publicKey->propId = *publicTemplate->GetBytes(CKA_ID, false, "");
        publicKey->propVerify = publicTemplate->GetBool(CKA_VERIFY, false, false);
        publicKey->propEncrypt = publicTemplate->GetBool(CKA_ENCRYPT, false, false);

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

// RSA private key

CK_RV RsaPrivateKey::GetKeyStruct(
    core::RsaPrivateKeyStruct* rsaKey
)
{
    DWORD dwKeyLen = 0;
    BYTE* pbKey = NULL;
    NTSTATUS status;
    if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPRIVATE_BLOB, 0, NULL, 0, &dwKeyLen, 0)) {
        THROW_NT_EXCEPTION(status);
    }
    pbKey = (BYTE*)malloc(dwKeyLen);
    if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPRIVATE_BLOB, 0, pbKey, dwKeyLen, &dwKeyLen, 0)) {
        free(pbKey);
        THROW_NT_EXCEPTION(status);
    }

    // BCRYPT_RSAKEY_BLOB
    BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbKey;
    // PublicExponent[cbPublicExp]  // Big-endian.
    PBYTE pbPublicExponent = (PBYTE)(pbKey + sizeof(BCRYPT_RSAKEY_BLOB));
    rsaKey->e = std::string((PCHAR)pbPublicExponent, header->cbPublicExp);
    // Modulus[cbModulus]           // Big-endian.
    PBYTE pbModulus = (PBYTE)(pbPublicExponent + header->cbPublicExp);
    rsaKey->n = std::string((PCHAR)pbModulus, header->cbModulus);
    // Prime1[cbPrime1]             // Big-endian.
    PBYTE pbPrime1 = (PBYTE)(pbModulus + header->cbModulus);
    rsaKey->p = std::string((PCHAR)pbPrime1, header->cbPrime1);
    // Prime2[cbPrime2]             // Big-endian.
    PBYTE pbPrime2 = (PBYTE)(pbPrime1 + header->cbPrime1);
    rsaKey->q = std::string((PCHAR)pbPrime2, header->cbPrime2);
    // Exponent1[cbPrime1]          // Big-endian.
    PBYTE pbExponent1 = (PBYTE)(pbPrime2 + header->cbPrime2);
    rsaKey->dp = std::string((PCHAR)pbExponent1, header->cbPrime1);
    // Exponent2[cbPrime2]          // Big-endian.
    PBYTE pbExponent2 = (PBYTE)(pbExponent1 + header->cbPrime1);
    rsaKey->dq = std::string((PCHAR)pbExponent2, header->cbPrime2);
    // Coefficient[cbPrime1]        // Big-endian.
    PBYTE pbCoefficient = (PBYTE)(pbExponent2 + header->cbPrime2);
    rsaKey->qi = std::string((PCHAR)pbCoefficient, header->cbPrime1);
    // PrivateExponent[cbModulus]   // Big-endian.
    PBYTE pbPrivateExponent = (PBYTE)(pbCoefficient + header->cbPrime1);
    rsaKey->d = std::string((PCHAR)pbPrivateExponent, header->cbModulus);

    free(pbKey);

    return CKR_OK;
}

// RSA public key

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetModulus)
{
    try {
        DWORD dwPublicKeyLen = 0;
        BYTE* pbPublicKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &dwPublicKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, pbPublicKey, dwPublicKeyLen, &dwPublicKeyLen, 0)) {
            free(pbPublicKey);
            THROW_NT_EXCEPTION(status);
        }

        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbPublicKey;
        BYTE* modulus = (BYTE*)(pbPublicKey + sizeof(BCRYPT_RSAKEY_BLOB) + header->cbPublicExp);

        CK_RV rv = this->GetBytes(pValue, pulValueLen, modulus, header->cbModulus);

        free(pbPublicKey);

        return rv;
    }
    CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetModulusBits)
{
    try {
        DWORD dwPublicKeyLen = 0;
        BYTE* pbPublicKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &dwPublicKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, pbPublicKey, dwPublicKeyLen, &dwPublicKeyLen, 0)) {
            free(pbPublicKey);
            THROW_NT_EXCEPTION(status);
        }

        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbPublicKey;

        CK_RV rv = this->GetNumber(pValue, pulValueLen, header->BitLength);

        free(pbPublicKey);

        return rv;
    }
    CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetPublicExponent)
{
    try {
        DWORD dwPublicKeyLen = 0;
        BYTE* pbPublicKey = NULL;
        NTSTATUS status;
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, NULL, 0, &dwPublicKeyLen, 0)) {
            THROW_NT_EXCEPTION(status);
        }
        pbPublicKey = (BYTE*)malloc(dwPublicKeyLen);
        if (status = NCryptExportKey(this->nkey->Get(), NULL, BCRYPT_RSAPUBLIC_BLOB, 0, pbPublicKey, dwPublicKeyLen, &dwPublicKeyLen, 0)) {
            free(pbPublicKey);
            THROW_NT_EXCEPTION(status);
        }

        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbPublicKey;

        CK_BYTE_PTR pbPublicExponent;
        if (header->cbPublicExp == 1) {
            pbPublicExponent = (CK_BYTE_PTR)malloc(1);
            pbPublicExponent[0] = 3;
        }
        else {
            pbPublicExponent = (CK_BYTE_PTR)malloc(3);
            pbPublicExponent[0] = 1;
            pbPublicExponent[1] = 0;
            pbPublicExponent[2] = 1;
        }
        CK_RV rv = this->GetBytes(pValue, pulValueLen, pbPublicExponent, header->cbPublicExp == 1 ? 1 : 3);

        free(pbPublicKey);
        free(pbPublicExponent);

        return rv;
    }
    CATCH_EXCEPTION;
}