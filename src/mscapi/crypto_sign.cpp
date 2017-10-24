#include "crypto.h"

#include "rsa.h"
#include "ec.h"

using namespace mscapi;

RsaPKCS1Sign::RsaPKCS1Sign(
    CK_BBOOL type
) :
    CryptoSign(type)
{
}

CK_RV RsaPKCS1Sign::Init(
    CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
    Scoped<core::Object>    key          /* signature key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Init(pMechanism, key);

#pragma region Get key
        ObjectKey* cryptoKey = NULL;
        if (type == CRYPTO_SIGN) {
            cryptoKey = dynamic_cast<RsaPrivateKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA private key");
            }
        }
        else {
            cryptoKey = dynamic_cast<RsaPublicKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA public key");
            }
        }
        this->key = cryptoKey->GetKey();
#pragma endregion

        if (this->key->IsCNG()) {
            // CNG
            CK_MECHANISM digestMechanism;
            switch (pMechanism->mechanism) {
            case CKM_SHA1_RSA_PKCS:
                digestMechanism = { CKM_SHA_1, NULL };
                digestAlgorithm = NCRYPT_SHA1_ALGORITHM;
                break;
            case CKM_SHA256_RSA_PKCS:
                digestMechanism = { CKM_SHA256, NULL };
                digestAlgorithm = NCRYPT_SHA256_ALGORITHM;
                break;
            case CKM_SHA384_RSA_PKCS:
                digestMechanism = { CKM_SHA384, NULL };
                digestAlgorithm = NCRYPT_SHA384_ALGORITHM;
                break;
            case CKM_SHA512_RSA_PKCS:
                digestMechanism = { CKM_SHA512, NULL };
                digestAlgorithm = NCRYPT_SHA512_ALGORITHM;
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Wrong Mechanism in use");
            }

            digest = Scoped<CryptoDigest>(new CryptoDigest);
            digest->Init(&digestMechanism);
        }
        else {
            // CAPI
            cDigest = crypt::Hash();

            ALG_ID algID = 0;
            switch (pMechanism->mechanism) {
            case CKM_SHA1_RSA_PKCS:
                algID = CALG_SHA1;
                break;
            case CKM_SHA256_RSA_PKCS:
                algID = CALG_SHA_256;
                break;
            case CKM_SHA384_RSA_PKCS:
                algID = CALG_SHA_384;
                break;
            case CKM_SHA512_RSA_PKCS:
                algID = CALG_SHA_512;
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Wrong Mechanism in use");
            }
            cDigest.Create(this->key->GetCKey(), algID);
        }

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPKCS1Sign::Update(
    CK_BYTE_PTR       pPart,     /* the data to sign/verify */
    CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Update(pPart, ulPartLen);

        if (key->IsCNG()) {
            // CNG
            digest->Update(pPart, ulPartLen);
        }
        else {
            // CAPI
            cDigest.Update(pPart, ulPartLen);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPKCS1Sign::Final(
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CryptoSign::Final(pSignature, pulSignatureLen);

        if (key->IsCNG()) {
            // CNG
            BCRYPT_PKCS1_PADDING_INFO paddingInfo = { digestAlgorithm };

            NTSTATUS status;

            // get size of signature
            ULONG ulSignatureLen;
            UCHAR hash[256] = { 0 };
            ULONG hashLen = 256;

            status = NCryptSignHash(key->GetNKey()->Get(), &paddingInfo, hash, hashLen, NULL, 0, &ulSignatureLen, BCRYPT_PAD_PKCS1);
            if (status) {
                THROW_NT_EXCEPTION(status, "NCryptSignHash");
            }

            if (pSignature == NULL_PTR) {
                *pulSignatureLen = ulSignatureLen;
            }
            else if (*pulSignatureLen < ulSignatureLen) {
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                digest->Final(hash, &hashLen);
                status = NCryptSignHash(key->GetNKey()->Get(), &paddingInfo, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, BCRYPT_PAD_PKCS1);
                active = false;
                if (status) {
                    THROW_NT_EXCEPTION(status, "NCryptSignHash");
                }
            }
        }
        else {
            // CAPI
            DWORD dwSignatureLen = 0;
            if (!CryptSignHash(cDigest.Get(), key->GetKeySpec(), NULL, 0, NULL, &dwSignatureLen)) {
                active = false;
                THROW_MSCAPI_EXCEPTION("CryptSignHash");
            }

            if (pSignature) {
                if (dwSignatureLen > *pulSignatureLen) {
                    THROW_PKCS11_BUFFER_TOO_SMALL();
                }
                *pulSignatureLen = dwSignatureLen;

                if (!CryptSignHash(cDigest.Get(), key->GetKeySpec(), NULL, 0, pSignature, pulSignatureLen)) {
                    active = false;
                    THROW_MSCAPI_EXCEPTION("CryptSignHash");
                }

                std::reverse(&pSignature[0], &pSignature[*pulSignatureLen]);

                active = false;
            }
            else {
                *pulSignatureLen = dwSignatureLen;
            }
        }

        return CKR_OK;
    }
    catch (Scoped<core::Exception> e) {
        active = false;
        Scoped<core::Exception> newExcep = EXCEPTION(e->what());
        newExcep->push(e);
        throw newExcep;
    }
    catch (...) {
        THROW_UNKNOWN_EXCEPTION();
    }
}

CK_RV RsaPKCS1Sign::Final(
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        if (key->IsCNG()) {
            // CNG
            NTSTATUS status;
            BCRYPT_PKCS1_PADDING_INFO paddingInfo = { digestAlgorithm };

            UCHAR hash[256];
            ULONG hashLen = 256;

            digest->Final(hash, &hashLen);

            status = NCryptVerifySignature(
                key->GetNKey()->Get(),
                &paddingInfo,
                hash, hashLen,
                pSignature, ulSignatureLen,
                BCRYPT_PAD_PKCS1
            );
            active = false;
            if (status) {
                if (status == NTE_BAD_SIGNATURE) {
                    return CKR_SIGNATURE_INVALID;
                }
                THROW_NT_EXCEPTION(status, "NCryptVerifySignature");
            }
        }
        else {
            // CAPI
            BOOL rv = CryptVerifySignature(cDigest.Get(), pSignature, ulSignatureLen, key->GetCKey()->Get(), NULL, 0);
            active = false;
            if (!rv) {
                NTSTATUS status = GetLastError();

                if (status == NTE_BAD_SIGNATURE) {
                    THROW_PKCS11_EXCEPTION(CKR_SIGNATURE_INVALID, "CryptVerifySignature");
                }
                THROW_NT_EXCEPTION(status, "CryptVerifySignature");
            }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

// RSA-PSS

RsaPSSSign::RsaPSSSign(
    CK_BBOOL type
) :
    CryptoSign(type),
    digest(Scoped<CryptoDigest>(new CryptoDigest()))
{
}

CK_RV RsaPSSSign::Init(
    CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
    Scoped<core::Object>    key          /* signature key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Init(pMechanism, key);

        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }

        CK_RSA_PKCS_PSS_PARAMS_PTR params = static_cast<CK_RSA_PKCS_PSS_PARAMS_PTR>(pMechanism->pParameter);
        if (params == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is not CK_RSA_PKCS_PSS_PARAMS");
        }

        salt = params->sLen;

        CK_MECHANISM digestMechanism;
        switch (pMechanism->mechanism) {
        case CKM_SHA1_RSA_PKCS_PSS:
            digestMechanism = { CKM_SHA_1, NULL };
            digestAlgorithm = NCRYPT_SHA1_ALGORITHM;
            break;
        case CKM_SHA256_RSA_PKCS_PSS:
            digestMechanism = { CKM_SHA256, NULL };
            digestAlgorithm = NCRYPT_SHA256_ALGORITHM;
            break;
        case CKM_SHA384_RSA_PKCS_PSS:
            digestMechanism = { CKM_SHA384, NULL };
            digestAlgorithm = NCRYPT_SHA384_ALGORITHM;
            break;
        case CKM_SHA512_RSA_PKCS_PSS:
            digestMechanism = { CKM_SHA512, NULL };
            digestAlgorithm = NCRYPT_SHA512_ALGORITHM;
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Wrong Mechanism in use");
        }

        ObjectKey* cryptoKey = NULL;
        if (type == CRYPTO_SIGN) {
            cryptoKey = dynamic_cast<RsaPrivateKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA private key");
            }
        }
        else {
            cryptoKey = dynamic_cast<RsaPublicKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA public key");
            }
        }

        this->key = cryptoKey->GetKey();

        digest->Init(&digestMechanism);

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPSSSign::Update(
    CK_BYTE_PTR       pPart,     /* the data to sign/verify */
    CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Update(pPart, ulPartLen);

        digest->Update(pPart, ulPartLen);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPSSSign::Final(
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {

        BCRYPT_PSS_PADDING_INFO paddingInfo = { digestAlgorithm, salt };

        NTSTATUS status;

        // get size of signature
        ULONG ulSignatureLen;
        UCHAR hash[256] = { 0 };
        ULONG hashLen = 256;
        status = NCryptSignHash(key->GetNKey()->Get(), &paddingInfo, hash, hashLen, NULL, 0, &ulSignatureLen, BCRYPT_PAD_PSS);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptSignHash");
        }

        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            digest->Final(hash, &hashLen);
            status = NCryptSignHash(key->GetNKey()->Get(), &paddingInfo, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, BCRYPT_PAD_PSS);
            active = false;
            if (status) {
                THROW_NT_EXCEPTION(status, "NCryptSignHash");
            }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPSSSign::Final(
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        NTSTATUS status;
        BCRYPT_PSS_PADDING_INFO paddingInfo = { digestAlgorithm, salt };

        UCHAR hash[256];
        ULONG hashLen = 256;

        digest->Final(hash, &hashLen);

        status = NCryptVerifySignature(
            key->GetNKey()->Get(),
            &paddingInfo,
            hash, hashLen,
            pSignature, ulSignatureLen,
            BCRYPT_PAD_PSS
        );
        active = false;
        if (status) {
            if (status == NTE_BAD_SIGNATURE) {
                return CKR_SIGNATURE_INVALID;
            }
            THROW_NT_EXCEPTION(status, "NCryptVerifySignature");
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

EcDSASign::EcDSASign(
    CK_BBOOL type
) :
    CryptoSign(type),
    digest(Scoped<CryptoDigest>(new CryptoDigest()))
{
}

CK_RV EcDSASign::Init(
    CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
    Scoped<core::Object>    key          /* signature key */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Init(pMechanism, key);

        CK_MECHANISM digestMechanism;
        switch (pMechanism->mechanism) {
        case CKM_ECDSA_SHA1:
            digestMechanism = { CKM_SHA_1, NULL };
            break;
        case CKM_ECDSA_SHA256:
            digestMechanism = { CKM_SHA256, NULL };
            break;
        case CKM_ECDSA_SHA384:
            digestMechanism = { CKM_SHA384, NULL };
            break;
        case CKM_ECDSA_SHA512:
            digestMechanism = { CKM_SHA512, NULL };
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        ObjectKey* cryptoKey = NULL;
        if (type == CRYPTO_SIGN) {
            cryptoKey = dynamic_cast<EcPrivateKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC private key");
            }
        }
        else {
            cryptoKey = dynamic_cast<EcPublicKey*>(key.get());
            if (!cryptoKey) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC public key");
            }
        }

        this->key = cryptoKey->GetKey();

        digest->Init(&digestMechanism);

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV EcDSASign::Update(
    CK_BYTE_PTR       pPart,     /* the data to sign/verify */
    CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoSign::Update(pPart, ulPartLen);

        digest->Update(pPart, ulPartLen);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV EcDSASign::Final(
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CryptoSign::Final(pSignature, pulSignatureLen);

        NTSTATUS status;

        // get size of signature
        ULONG ulSignatureLen;
        UCHAR hash[256] = { 0 };
        ULONG hashLen = 256;
        status = NCryptSignHash(key->GetNKey()->Get(), NULL, hash, hashLen, NULL, 0, &ulSignatureLen, 0);
        if (status) {
            THROW_NT_EXCEPTION(status, "NCryptSignHash");
        }

        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            digest->Final(hash, &hashLen);
            status = NCryptSignHash(key->GetNKey()->Get(), NULL, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, 0);
            active = false;
            if (status) {
                THROW_NT_EXCEPTION(status, "NCryptSignHash");
            }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV EcDSASign::Final(
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        NTSTATUS status;

        UCHAR hash[256];
        ULONG hashLen = 256;

        digest->Final(hash, &hashLen);

        status = NCryptVerifySignature(
            key->GetNKey()->Get(),
            NULL,
            hash, hashLen,
            pSignature, ulSignatureLen,
            0
        );
        active = false;
        if (status) {
            if (status == NTE_BAD_SIGNATURE) {
                return CKR_SIGNATURE_INVALID;
            }
            THROW_NT_EXCEPTION(status, "NCryptVerifySignature");
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}