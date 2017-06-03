#include "../crypto.h"

using namespace osx;

CK_RV osx::CryptoDigest::Init
(
    CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
    try {
        core::CryptoDigest::Init(pMechanism);

        mechType = pMechanism->mechanism;
        switch (mechType) {
        case CKM_SHA_1:
            CC_SHA1_Init(&sha1Alg);
            break;
        case CKM_SHA256:
            CC_SHA256_Init(&sha256Alg);
            break;
        case CKM_SHA384:
            CC_SHA384_Init(&sha512Alg);
            break;
        case CKM_SHA512:
            CC_SHA512_Init(&sha512Alg);
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Unsupported mechanism in use.");
        }

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::CryptoDigest::Update(
    CK_BYTE_PTR       pPart,     /* data to be digested */
    CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    try {
        core::CryptoDigest::Update(pPart, ulPartLen);

        switch (mechType) {
        case CKM_SHA_1:
            CC_SHA1_Update(&sha1Alg, pPart, ulPartLen);
            break;
        case CKM_SHA256:
            CC_SHA256_Update(&sha256Alg, pPart, ulPartLen);
            break;
        case CKM_SHA384:
            CC_SHA384_Update(&sha512Alg, pPart, ulPartLen);
            break;
        case CKM_SHA512:
            CC_SHA512_Update(&sha512Alg, pPart, ulPartLen);
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Unsupported mechanism in use.");
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::CryptoDigest::Final(
    CK_BYTE_PTR       pDigest,      /* gets the message digest */
    CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
    try {
        core::CryptoDigest::Final(pDigest, pulDigestLen);

        CK_ULONG ulDigestLen = GetDigestLength(mechType);
        if (!pDigest) {
            puts("get size");
            *pulDigestLen = ulDigestLen;
        } else if (*pulDigestLen < ulDigestLen) {
            THROW_PKCS11_BUFFER_TOO_SMALL();
        } else {
            *pulDigestLen = ulDigestLen;
            
            switch (mechType) {
            case CKM_SHA_1:
                CC_SHA1_Final(pDigest, &sha1Alg);
                break;
            case CKM_SHA256:
                CC_SHA256_Final(pDigest, &sha256Alg);
                break;
            case CKM_SHA384:
                CC_SHA384_Final(pDigest, &sha512Alg);
                break;
            case CKM_SHA512:
                CC_SHA512_Final(pDigest, &sha512Alg);
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Unsupported mechanism in use.");
            }
        }

        active = false;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_ULONG osx::CryptoDigest::GetDigestLength(
    CK_MECHANISM_TYPE       mechanism
)
{
    try {
        switch (mechType) {
            case CKM_SHA_1:
                return CC_SHA1_DIGEST_LENGTH;
            case CKM_SHA256:
                return CC_SHA256_DIGEST_LENGTH;
            case CKM_SHA384:
                return CC_SHA384_DIGEST_LENGTH;
            case CKM_SHA512:
                return CC_SHA512_DIGEST_LENGTH;
            default:
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Unsupported mechanism in use.");
            }
    }
    CATCH_EXCEPTION
}