#include "rsa.h"
#include "helper.h"
#include "ncrypt/provider.h"

using namespace mscapi;

Scoped<CryptoKeyPair> RsaKey::Generate(
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

        Scoped<ncrypt::Key> nKey;
        auto pszAlgorithm = NCRYPT_RSA_ALGORITHM;
        if (!privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue()) {
            nKey = provider->CreatePersistedKey(pszAlgorithm, NULL, 0, 0);
        }
        else {
            nKey = provider->CreatePersistedKey(pszAlgorithm, provider->GenerateRandomName()->c_str(), 0, 0);
        }

        // Public exponent
        auto publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
        char PUBLIC_EXPONENT_65537[3] = { 1, 0, 1 };
        if (!(publicExponent->size() == 3 && !memcmp(publicExponent->data(), PUBLIC_EXPONENT_65537, 3))) {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
        }
        // Modulus length
        nKey->SetNumber(NCRYPT_LENGTH_PROPERTY, publicTemplate->GetNumber(CKA_MODULUS_BITS, true));
        // Key Usage
        ULONG keyUsage = 0;
        if (privateTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
            keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
        }
        if (publicTemplate->GetBool(CKA_ENCRYPT, false, false) || privateTemplate->GetBool(CKA_DECRYPT, false, false) ||
            publicTemplate->GetBool(CKA_WRAP, false, false) || privateTemplate->GetBool(CKA_UNWRAP, false, false)) {
            keyUsage |= NCRYPT_ALLOW_DECRYPT_FLAG;
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

// RSA private key

void RsaPrivateKey::FillPublicKeyStruct()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        auto nkey = GetKey()->GetNKey();
        auto buffer = nkey->Export(BCRYPT_RSAPUBLIC_BLOB, 0);
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
            LOGGER_ERROR("Cannot get NCRYPT_KEY_USAGE_PROPERTY");
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
    LOGGER_FUNCTION_BEGIN;

    try {
        auto buffer = GetKey()->GetNKey()->Export(BCRYPT_RSAFULLPRIVATE_BLOB, 0);
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

void mscapi::RsaPrivateKey::FillPinData()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NCRYPT_UI_POLICY policy;
        ULONG size = sizeof(NCRYPT_UI_POLICY);
        GetKey()->GetNKey()->GetParam(NCRYPT_UI_POLICY_PROPERTY, (PBYTE)&policy, &size);

        std::wstring wstrDesciption(L"");
        if (policy.pszFriendlyName) {
            std::wstring wstrValue(policy.pszFriendlyName);
            std::string strValue(wstrValue.begin(), wstrValue.end());

            ItemByType(CKA_PIN_FRIENDLY_NAME)->SetValue((CK_VOID_PTR)strValue.c_str(), strValue.length());
        }
        if (policy.pszDescription) {
            std::wstring wstrValue(policy.pszDescription);
            std::string strValue(wstrValue.begin(), wstrValue.end());

            ItemByType(CKA_PIN_DESCRIPTION)->SetValue((CK_VOID_PTR)strValue.c_str(), strValue.length());
        }
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::GetValue
(
    CK_ATTRIBUTE_PTR  attr
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        switch (attr->type) {
        case CKA_DECRYPT:
        case CKA_UNWRAP:
        case CKA_SIGN:
        case CKA_MODULUS:
        case CKA_PUBLIC_EXPONENT:
        {
            if (ItemByType(CKA_MODULUS)->IsEmpty()) {
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
        case CKA_PIN_FRIENDLY_NAME:
        case CKA_PIN_DESCRIPTION:
            if (ItemByType(attr->type)->IsEmpty()) {
                FillPinData();
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
    LOGGER_FUNCTION_BEGIN;

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
        provider.Open(wstrProvName.c_str(), 0);

        auto attrToken = ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->ToValue();
        auto attrExtractable = ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->ToValue();

        std::wstring wstrContainerName = L"";
        auto wstrRandomName = provider.GenerateRandomName();
        if (wstrScope.length()) {
            wstrContainerName += wstrScope + wstrRandomName->c_str();
        }
        else {
            wstrContainerName = wstrRandomName->c_str();
        }

        Scoped<ncrypt::Key> nkey;
        if (attrToken && !wstrScope.length()) {
            Scoped<std::wstring> wstrFriendlyName = wstrRandomName;
            Scoped<std::wstring> wstrDescription(new std::wstring(L""));
            NCRYPT_UI_POLICY policy;
            policy.dwVersion = 1;
            policy.dwFlags = NCRYPT_UI_FORCE_HIGH_PROTECTION_FLAG;
            policy.pszCreationTitle = NULL;
            {
                // CKA_PIN_FRIENDLY_NAME
                auto value = ItemByType(CKA_PIN_FRIENDLY_NAME)->ToString();
                if (value->length() > 0) {
                    wstrFriendlyName = Scoped<std::wstring>(new std::wstring(value->begin(), value->end()));
                }
            }

            {
                // CKA_PIN_DESCRIPTION
                auto value = ItemByType(CKA_PIN_DESCRIPTION)->ToString();
                if (value->length() > 0) {
                    wstrDescription = Scoped<std::wstring>(new std::wstring(value->begin(), value->end()));
                }
                else {
                    if (ItemByType(CKA_SIGN)->ToBool()) {
                        *wstrDescription.get() += L"Signing";
                    }
                    if (ItemByType(CKA_DECRYPT)->ToBool()) {
                        if (wstrDescription->length() > 0) {
                            *wstrDescription.get() += L", ";
                        }
                        *wstrDescription.get() += L"Encryption";
                    }
                }
            }
            policy.pszFriendlyName = wstrFriendlyName->c_str();
            policy.pszDescription = wstrDescription->c_str();

            nkey = provider.SetKey(
                originalKey->GetKey()->GetNKey(),
                LEGACY_RSAPRIVATE_BLOB,
                attrToken ? wstrContainerName.c_str() : NULL,
                (attrToken && attrExtractable) || !attrToken,
                &policy
            );
        }
        else {
            nkey = provider.SetKey(
                originalKey->GetKey()->GetNKey(),
                LEGACY_RSAPRIVATE_BLOB,
                attrToken ? wstrContainerName.c_str() : NULL,
                (attrToken && attrExtractable) || !attrToken, 
                NULL
            );
        }

        SetKey(nkey);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPrivateKey::Destroy()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        GetKey()->GetNKey()->Delete(0);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}


// RSA public key

void RsaPublicKey::FillKeyStruct()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        auto nkey = GetKey()->GetNKey();
        auto buffer = nkey->Export(BCRYPT_RSAPUBLIC_BLOB, 0);
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
    LOGGER_FUNCTION_BEGIN;

    try {
        switch (attr->type) {
        case CKA_VERIFY:
        case CKA_ENCRYPT:
        case CKA_WRAP:
        case CKA_MODULUS:
        case CKA_MODULUS_BITS:
        case CKA_PUBLIC_EXPONENT: {
            if (ItemByType(CKA_MODULUS)->IsEmpty()) {
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
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Template tmpl(pTemplate, ulCount);
        core::RsaPublicKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        Scoped<Buffer> buffer(new Buffer);

        // Get params
        auto publicExponent = tmpl.GetBytes(CKA_PUBLIC_EXPONENT, true, "");
        auto modulus = tmpl.GetBytes(CKA_MODULUS, true, "");

        // fill bcrypt blob
        buffer->resize(sizeof(BCRYPT_RSAKEY_BLOB));
        BCRYPT_RSAKEY_BLOB* header = (BCRYPT_RSAKEY_BLOB*)buffer->data();
        header->Magic = BCRYPT_RSAPUBLIC_MAGIC;
        header->BitLength = modulus->size() << 3;
        header->cbModulus = modulus->size();
        header->cbPublicExp = publicExponent->size();

        buffer->insert(buffer->end(), publicExponent->begin(), publicExponent->end());
        buffer->insert(buffer->end(), modulus->begin(), modulus->end());

        Scoped<ncrypt::Key> nKey(new ncrypt::Key);
        nKey->Import(BCRYPT_RSAPUBLIC_BLOB, buffer);
        SetKey(key);

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
    LOGGER_FUNCTION_BEGIN;

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

        SetKey(originalKey->GetKey());

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPublicKey::Destroy()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void mscapi::RsaPublicKey::Import(Scoped<Buffer> data)
{
    LOGGER_FUNCTION_BEGIN;

    try {

    }
    CATCH_EXCEPTION
}