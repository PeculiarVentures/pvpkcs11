#include "crypto.h"

#include "helper.h"

using namespace mscapi;

CryptoDigest::~CryptoDigest()
{
    Dispose();
}

CK_RV CryptoDigest::Init
(
    CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
    try {
        core::CryptoDigest::Init(pMechanism);

        LPCWSTR pszAlgorithm;

        switch (pMechanism->mechanism) {
        case CKM_SHA_1:
            pszAlgorithm = BCRYPT_SHA1_ALGORITHM;
            break;
        case CKM_SHA256:
            pszAlgorithm = BCRYPT_SHA256_ALGORITHM;
            break;
        case CKM_SHA384:
            pszAlgorithm = BCRYPT_SHA384_ALGORITHM;
            break;
        case CKM_SHA512:
            pszAlgorithm = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "Unsupported mechanism in use.");
        }
        algorithm = Scoped<bcrypt::Algorithm>(new bcrypt::Algorithm());
        algorithm->Open(pszAlgorithm, MS_PRIMITIVE_PROVIDER, 0);
        NTSTATUS status = BCryptCreateHash(algorithm->Get(), &hDigest, NULL, 0, NULL, 0, 0);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoDigest::Update(
    CK_BYTE_PTR       pPart,     /* data to be digested */
    CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
    try {
        core::CryptoDigest::Update(pPart, ulPartLen);

        NTSTATUS status = BCryptHashData(hDigest, pPart, ulPartLen, 0);
        if (status) {
            THROW_NT_EXCEPTION(status);
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoDigest::Final(
    CK_BYTE_PTR       pDigest,      /* gets the message digest */
    CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
    try {
        core::CryptoDigest::Final(pDigest, pulDigestLen);

        NTSTATUS status;

        // Get digest length
        ULONG ulHashLength;
        ULONG ulDataLen = sizeof(ULONG);
        status = BCryptGetProperty(hDigest, BCRYPT_HASH_LENGTH, (PUCHAR)&ulHashLength, ulDataLen, &ulDataLen, 0);
        if (status) {
            Dispose();
            THROW_NT_EXCEPTION(status);
        }

        if (pDigest == NULL) {
            *pulDigestLen = ulHashLength;
        }
        else if (*pulDigestLen < ulHashLength) {
            *pulDigestLen = ulHashLength;
            THROW_PKCS11_BUFFER_TOO_SMALL();
        }
        else {
            *pulDigestLen = ulHashLength;
            status = BCryptFinishHash(hDigest, pDigest, *pulDigestLen, 0);
            Dispose();
            if (status) {
                THROW_NT_EXCEPTION(status);
            }
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void CryptoDigest::Dispose()
{
    if (hDigest) {
        BCryptDestroyHash(hDigest);
        hDigest = NULL;
    }
    active = false;
}