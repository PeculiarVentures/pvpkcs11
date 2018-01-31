#include "../core/excep.h"

#include "helper.h"
#include "session.h"
#include "crypto.h"

#include "rsa.h"
#include "ec.h"
#include "aes.h"

#include "ncrypt/provider.h"

#include "certificate.h"
#include "data.h"

using namespace mscapi;

Session::Session() : core::Session()
{
    digest = Scoped<CryptoDigest>(new CryptoDigest());
    sign = Scoped<CryptoSign>(new CryptoSign(CRYPTO_SIGN));
    verify = Scoped<CryptoSign>(new CryptoSign(CRYPTO_VERIFY));
    encrypt = Scoped<CryptoEncrypt>(new CryptoEncrypt(CRYPTO_ENCRYPT));
    decrypt = Scoped<CryptoEncrypt>(new CryptoEncrypt(CRYPTO_DECRYPT));
}

Session::~Session()
{
}

CK_RV mscapi::Session::GenerateRandom(
    CK_BYTE_PTR       pRandomData, /* receives the random data */
    CK_ULONG          ulRandomLen  /* # of bytes to generate */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::GenerateRandom(pRandomData, ulRandomLen);

        NTSTATUS status = BCryptGenRandom(NULL, pRandomData, ulRandomLen, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (status) {
            THROW_NT_EXCEPTION(status, "BCryptGenRandom");
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV Session::VerifyInit(
    CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
    CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::VerifyInit(pMechanism, hKey);

        if (verify->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            verify = Scoped<CryptoSign>(new RsaPKCS1Sign(CRYPTO_VERIFY));
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            verify = Scoped<CryptoSign>(new RsaPSSSign(CRYPTO_VERIFY));
            break;
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            verify = Scoped<CryptoSign>(new EcDSASign(CRYPTO_VERIFY));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return verify->Init(pMechanism, GetObject(hKey));
    }
    CATCH_EXCEPTION
}

CK_RV Session::SignInit(
    CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::SignInit(pMechanism, hKey);

        if (sign->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS:
            sign = Scoped<CryptoSign>(new RsaPKCS1Sign(CRYPTO_SIGN));
            break;
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS_PSS:
            sign = Scoped<CryptoSign>(new RsaPSSSign(CRYPTO_SIGN));
            break;
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
            sign = Scoped<CryptoSign>(new EcDSASign(CRYPTO_SIGN));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return sign->Init(pMechanism, GetObject(hKey));
    }
    CATCH_EXCEPTION
}

CK_RV Session::EncryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::EncryptInit(
            pMechanism,
            hKey
        );

        if (encrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_OAEP:
            encrypt = Scoped<CryptoRsaOAEPEncrypt>(new CryptoRsaOAEPEncrypt(CRYPTO_ENCRYPT));
            break;
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
            encrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_ENCRYPT));
            break;
        case CKM_AES_GCM:
            encrypt = Scoped<CryptoAesGCMEncrypt>(new CryptoAesGCMEncrypt(CRYPTO_ENCRYPT));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return encrypt->Init(
            pMechanism,
            GetObject(hKey)
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Session::DecryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::DecryptInit(
            pMechanism,
            hKey
        );

        if (decrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_RSA_PKCS_OAEP:
            decrypt = Scoped<CryptoRsaOAEPEncrypt>(new CryptoRsaOAEPEncrypt(CRYPTO_DECRYPT));
            break;
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
            decrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_DECRYPT));
            break;
        case CKM_AES_GCM:
            decrypt = Scoped<CryptoAesGCMEncrypt>(new CryptoAesGCMEncrypt(CRYPTO_DECRYPT));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return decrypt->Init(
            pMechanism,
            GetObject(hKey)
        );
    }
    CATCH_EXCEPTION;
}

CK_RV Session::DeriveKey
(
    CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
    CK_OBJECT_HANDLE     hBaseKey,          /* base key */
    CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
    CK_ULONG             ulAttributeCount,  /* template length */
    CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::Session::DeriveKey(
            pMechanism,
            hBaseKey,
            pTemplate,
            ulAttributeCount,
            phKey
        );

        auto baseKey = GetObject(hBaseKey);
        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulAttributeCount));

        Scoped<core::Object> derivedKey;
        switch (pMechanism->mechanism) {
        case CKM_ECDH1_DERIVE: {
            derivedKey = EcKey::DeriveKey(
                pMechanism,
                baseKey,
                tmpl
            );
        }
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        // add key to session's objects
        objects.add(baseKey);

        // set handle for key
        *phKey = derivedKey->handle;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}
