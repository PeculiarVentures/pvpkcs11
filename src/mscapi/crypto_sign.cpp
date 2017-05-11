#include "crypto.h"

#include "rsa.h";
#include "ec.h";

using namespace mscapi;

RsaPKCS1Sign::RsaPKCS1Sign(
    CK_BBOOL type
) :
    CryptoSign(type),
    digest(Scoped<CryptoDigest>(new CryptoDigest()))
{
}

CK_RV RsaPKCS1Sign::Init(
    CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
    Scoped<core::Object>    key          /* signature key */
)
{
    try {
        core::CryptoSign::Init(pMechanism, key);

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

        if (type == CRYPTO_SIGN) {
            if (!dynamic_cast<RsaPrivateKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA private key");
            }
        }
        else {
            if (!dynamic_cast<RsaPublicKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA public key");
            }
        }

        this->key = dynamic_cast<CryptoKey*>(key.get());

        digest->Init(&digestMechanism);

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
    try {
        core::CryptoSign::Update(pPart, ulPartLen);

        digest->Update(pPart, ulPartLen);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPKCS1Sign::Final(
    CK_BYTE_PTR       pSignature,      /* gets the signature */
    CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
    try {
        CryptoSign::Final(pSignature, pulSignatureLen);

        BCRYPT_PKCS1_PADDING_INFO paddingInfo = { digestAlgorithm };

        NTSTATUS status;

        // get size of signature
        ULONG ulSignatureLen;
        UCHAR hash[256] = { 0 };
        ULONG hashLen = 256;
        status = NCryptSignHash(key->nkey->Get(), &paddingInfo, hash, hashLen, NULL, 0, &ulSignatureLen, BCRYPT_PAD_PKCS1);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            digest->Final(hash, &hashLen);
            status = NCryptSignHash(key->nkey->Get(), &paddingInfo, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, BCRYPT_PAD_PKCS1);
            active = false;
            if (status) {
                THROW_NT_EXCEPTION(status);
            }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV RsaPKCS1Sign::Final(
    CK_BYTE_PTR       pSignature,     /* signature to verify */
    CK_ULONG          ulSignatureLen  /* signature length */
)
{
    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        NTSTATUS status;
        BCRYPT_PKCS1_PADDING_INFO paddingInfo = { digestAlgorithm };

        UCHAR hash[256];
        ULONG hashLen = 256;

        digest->Final(hash, &hashLen);

        status = NCryptVerifySignature(
            key->nkey->Get(),
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
            THROW_NT_EXCEPTION(status);
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

        if (type == CRYPTO_SIGN) {
            if (!dynamic_cast<RsaPrivateKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA private key");
            }
        }
        else {
            if (!dynamic_cast<RsaPublicKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not RSA public key");
            }
        }

        this->key = dynamic_cast<CryptoKey*>(key.get());

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
    try {

        BCRYPT_PSS_PADDING_INFO paddingInfo = { digestAlgorithm, salt };

        NTSTATUS status;

        // get size of signature
        ULONG ulSignatureLen;
        UCHAR hash[256] = { 0 };
        ULONG hashLen = 256;
        status = NCryptSignHash(key->nkey->Get(), &paddingInfo, hash, hashLen, NULL, 0, &ulSignatureLen, BCRYPT_PAD_PSS);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            digest->Final(hash, &hashLen);
            status = NCryptSignHash(key->nkey->Get(), &paddingInfo, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, BCRYPT_PAD_PSS);
            active = false;
            if (status) {
                THROW_NT_EXCEPTION(status);
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
    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        NTSTATUS status;
        BCRYPT_PSS_PADDING_INFO paddingInfo = { digestAlgorithm, salt };

        UCHAR hash[256];
        ULONG hashLen = 256;

        digest->Final(hash, &hashLen);

        status = NCryptVerifySignature(
            key->nkey->Get(),
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
            THROW_NT_EXCEPTION(status);
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

        if (type == CRYPTO_SIGN) {
            if (!dynamic_cast<EcPrivateKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC private key");
            }
        }
        else {
            if (!dynamic_cast<EcPublicKey*>(key.get())) {
                THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key is not EC public key");
            }
        }

        this->key = dynamic_cast<CryptoKey*>(key.get());

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
    try {
        CryptoSign::Final(pSignature, pulSignatureLen);

        NTSTATUS status;

        // get size of signature
        ULONG ulSignatureLen;
        UCHAR hash[256] = { 0 };
        ULONG hashLen = 256;
        status = NCryptSignHash(key->nkey->Get(), NULL, hash, hashLen, NULL, 0, &ulSignatureLen, 0);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        if (pSignature == NULL_PTR) {
            *pulSignatureLen = ulSignatureLen;
        }
        else if (*pulSignatureLen < ulSignatureLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            digest->Final(hash, &hashLen);
            status = NCryptSignHash(key->nkey->Get(), NULL, hash, hashLen, pSignature, ulSignatureLen, pulSignatureLen, 0);
            active = false;
            if (status) {
                THROW_NT_EXCEPTION(status);
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
    try {
        CryptoSign::Final(pSignature, ulSignatureLen);

        NTSTATUS status;

        UCHAR hash[256];
        ULONG hashLen = 256;

        digest->Final(hash, &hashLen);

        status = NCryptVerifySignature(
            key->nkey->Get(),
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
            THROW_NT_EXCEPTION(status);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}