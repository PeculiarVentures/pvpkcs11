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

        Scoped<ncrypt::Key> key;
        auto pszAlgorithm = NCRYPT_RSA_ALGORITHM;
        if (!privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue()) {
            key = provider->CreatePersistedKey(pszAlgorithm, NULL, 0, 0);
        }
        else {
            key = provider->CreatePersistedKey(pszAlgorithm, provider->GenerateRandomName()->c_str(), 0, 0);
        }

        // Public exponent
        auto publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
        char PUBLIC_EXPONENT_65537[3] = { 1,0,1 };
        if (!(publicExponent->size() == 3 && !memcmp(publicExponent->data(), PUBLIC_EXPONENT_65537, 3))) {
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

        auto attrToken = privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue();
        auto attrExtractable = privateKey->ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->ToValue();
        if ((attrToken && attrExtractable) || !attrToken) {
            // Make all session keys extractable. It allows to copy keys from session to storage via export/import
            // This is extractable only for internal usage. Key object will have CKA_EXTRACTABLE with setted value
            key->SetNumber(NCRYPT_EXPORT_POLICY_PROPERTY, NCRYPT_ALLOW_PLAINTEXT_EXPORT_FLAG, NCRYPT_PERSIST_FLAG);
        }

        key->Finalize();

        privateKey->Assign(key);
        publicKey->Assign(key);

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

// RSA private key

void RsaPrivateKey::FillPublicKeyStruct()
{
    try {
        auto buffer = nkey->ExportKey(BCRYPT_RSAPUBLIC_BLOB, 0);
        BYTE* pbKey = buffer->data();

        // BCRYPT_RSAKEY_BLOB
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbKey;
        // PublicExponent[cbPublicExp]  // Big-endian.
        PBYTE pbPublicExponent = (PBYTE)(pbKey + sizeof(BCRYPT_RSAKEY_BLOB));
        ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(pbPublicExponent, header->cbPublicExp);
        // Modulus[cbModulus]           // Big-endian.
        PBYTE pbModulus = (PBYTE)(pbPublicExponent + header->cbPublicExp);
        ItemByType(CKA_MODULUS)->SetValue(pbModulus, header->cbModulus);

        DWORD keyUsage = NCRYPT_ALLOW_SIGNING_FLAG | NCRYPT_ALLOW_DECRYPT_FLAG;
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
        if (keyUsage & NCRYPT_ALLOW_DECRYPT_FLAG) {
            ItemByType(CKA_DECRYPT)->To<core::AttributeBool>()->Set(true);
            ItemByType(CKA_UNWRAP)->To<core::AttributeBool>()->Set(true);
        }
    }
    CATCH_EXCEPTION
}

void RsaPrivateKey::FillPrivateKeyStruct()
{
    try {
        auto buffer = nkey->ExportKey(BCRYPT_RSAFULLPRIVATE_BLOB, 0);
        BYTE* pbKey = buffer->data();

        // BCRYPT_RSAKEY_BLOB
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)pbKey;
        // PublicExponent[cbPublicExp]  // Big-endian.
        PBYTE pbPublicExponent = (PBYTE)(pbKey + sizeof(BCRYPT_RSAKEY_BLOB));
        // Modulus[cbModulus]           // Big-endian.
        PBYTE pbModulus = (PBYTE)(pbPublicExponent + header->cbPublicExp);
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
        {
            if (ItemByType(attr->type)->IsEmpty()) {
                FillPublicKeyStruct();
            }
            break;
        }
        case CKA_PRIME_1:
        case CKA_PRIME_2:
        case CKA_EXPONENT_1:
        case CKA_EXPONENT_2:
        case CKA_PRIVATE_EXPONENT:
        {
            if (ItemByType(attr->type)->IsEmpty()) {
                FillPrivateKeyStruct();
            }
            break;
        }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
    try {
        core::RsaPrivateKey::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        RsaPrivateKey* originalKey = dynamic_cast<RsaPrivateKey*>(object.get());
        if (!originalKey) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Original key must be RsaPrivateKey");
        }

        ncrypt::Provider provider;
        provider.Open(MS_KEY_STORAGE_PROVIDER, 0);

        auto attrToken = ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue();
        auto attrExtractable = ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->ToValue();

        nkey = ncrypt::CopyKeyToProvider(
            originalKey->nkey.get(),
            BCRYPT_RSAFULLPRIVATE_BLOB,
            &provider,
            attrToken ? provider.GenerateRandomName()->c_str() : NULL,
            (attrToken && attrExtractable) || !attrToken
        );

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::Destroy()
{
    try {
        nkey->Delete(0);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void RsaPrivateKey::OnKeyAssigned()
{
    try {
        FillPublicKeyStruct();
    }
    CATCH_EXCEPTION
}

// RSA public key

void RsaPublicKey::FillKeyStruct()
{
    try {
        auto buffer = nkey->ExportKey(BCRYPT_RSAPUBLIC_BLOB, 0);
        BYTE* pbKey = buffer->data();

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

        auto keyUsage = nkey->GetNumber(NCRYPT_KEY_USAGE_PROPERTY);
        if (keyUsage & NCRYPT_ALLOW_SIGNING_FLAG) {
            ItemByType(CKA_VERIFY)->To<core::AttributeBool>()->Set(true);
        }
        if (keyUsage & NCRYPT_ALLOW_DECRYPT_FLAG) {
            ItemByType(CKA_ENCRYPT)->To<core::AttributeBool>()->Set(true);
            ItemByType(CKA_WRAP)->To<core::AttributeBool>()->Set(true);
        }
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

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPublicKey::CreateValues
(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::Template tmpl(pTemplate, ulCount);
        core::RsaPublicKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        Scoped<Buffer> buffer(new Buffer);


        // Named curve
        auto publicExponent = tmpl.GetBytes(CKA_PUBLIC_EXPONENT, true, "");
        auto modulus = tmpl.GetBytes(CKA_MODULUS, true, "");

        buffer->resize(sizeof(BCRYPT_RSAKEY_BLOB));
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)buffer->data();
        header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header->BitLength = modulus->size() << 3;
        header->cbModulus = modulus->size();
        header->cbPublicExp = publicExponent->size();

        buffer->insert(buffer->end(), publicExponent->begin(), publicExponent->end());
        buffer->insert(buffer->end(), modulus->begin(), modulus->end());

        ncrypt::Provider provider;
        provider.Open(NULL, 0);

        auto key = provider.ImportKey(BCRYPT_RSAPUBLIC_BLOB, buffer->data(), buffer->size(), 0);
        Assign(key);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPublicKey::CopyValues(
    Scoped<core::Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR        pTemplate,  /* specifies attributes */
    CK_ULONG                ulCount     /* attributes in template */
)
{
    try {
        core::RsaPublicKey::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        RsaPublicKey* originalKey = dynamic_cast<RsaPublicKey*>(object.get());
        if (!originalKey) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Original key must be RsaPrivateKey");
        }

        nkey = originalKey->nkey;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPublicKey::Destroy()
{
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void RsaPublicKey::OnKeyAssigned()
{
    try {
        FillKeyStruct();
    }
    CATCH_EXCEPTION
}