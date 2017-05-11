#include "aes.h"
#include "helper.h"

#include "bcrypt.h"

using namespace mscapi;

Scoped<core::SecretKey> AesKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> tmpl
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_AES_KEY_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        ULONG ulKeyLength = tmpl->GetNumber(CKA_VALUE_LEN, true, 0);

        switch (ulKeyLength) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE must be 16, 24 or 32");
        }

        Scoped<bcrypt::Algorithm> provider(new bcrypt::Algorithm());
        provider->Open(BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

        auto secretKey = provider->GenerateRandom(ulKeyLength);

        auto key = provider->GenerateKey(NULL, 0, (PUCHAR)secretKey->c_str(), secretKey->length(), 0);

        Scoped<AesKey> aesKey(new AesKey(key));

        // Set properties
        aesKey->propId = *tmpl->GetBytes(CKA_ID, false, "");
        aesKey->propExtractable = tmpl->GetBool(CKA_EXTRACTABLE, false, false);
        aesKey->propSign = tmpl->GetBool(CKA_SIGN, false, false);
        aesKey->propVerify = tmpl->GetBool(CKA_VERIFY, false, false);
        aesKey->propEncrypt = tmpl->GetBool(CKA_ENCRYPT, false, false);
        aesKey->propDecrypt = tmpl->GetBool(CKA_DECRYPT, false, false);

        aesKey->propValueLen = tmpl->GetNumber(CKA_VALUE_LEN, true, 0);
        aesKey->propValue = secretKey;

        return aesKey;
    }
    CATCH_EXCEPTION
}

// AES-CBC

CryptoAesCBCEncrypt::CryptoAesCBCEncrypt(
    CK_BBOOL type
) : CryptoEncrypt(type)
{
}

CK_RV CryptoAesCBCEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    key
)
{
    try {
        core::CryptoEncrypt::Init(
            pMechanism,
            key
        );

        if (pMechanism->mechanism != CKM_AES_CBC_PAD) {
            THROW_PKCS11_MECHANISM_INVALID();
        }
        if (!(key && key.get())) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
        }
        this->key = dynamic_cast<AesKey*>(key.get());
        if (!this->key) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key must be AES");
        }

        // IV
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }
        if (pMechanism->ulParameterLen != 16) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "AES-CBC IV must be 16 bytes");
        }
        iv = Scoped<std::string>(new std::string((PCHAR)pMechanism->pParameter, pMechanism->ulParameterLen));

        provider = Scoped<bcrypt::Algorithm>(new bcrypt::Algorithm());
        provider->Open(BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

        provider->SetParam(BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, lstrlenW(BCRYPT_CHAIN_MODE_CBC));
        provider->SetParam(BCRYPT_INITIALIZATION_VECTOR, (PUCHAR)iv->c_str(), iv->length());

        active = true;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesCBCEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
    try {
        // NTSTATUS status = BCryptEncrypt()
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesCBCEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
    try {

    }
    CATCH_EXCEPTION
}