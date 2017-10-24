#pragma once

#include "../stdafx.h"
#include "../core/crypto.h"

#include "bcrypt/provider.h"
#include "crypt/hash.h"
#include "key.h"
#include "crypto_key.h"
#include "helper.h"

namespace mscapi {

    class CryptoDigest : public core::CryptoDigest {
    public:
        CryptoDigest() : core::CryptoDigest(), hDigest(NULL) {}

        ~CryptoDigest();

        CK_RV Init
        (
            CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
        );

        CK_RV Update(
            CK_BYTE_PTR       pPart,     /* data to be digested */
            CK_ULONG          ulPartLen  /* bytes of data to be digested */
        );

        CK_RV Final(
            CK_BYTE_PTR       pDigest,      /* gets the message digest */
            CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
        );

    protected:
        Scoped<bcrypt::Provider>  algorithm;
        BCRYPT_HASH_HANDLE        hDigest;

        void Dispose();
    };

    Scoped<Buffer> Digest(
        CK_MECHANISM_TYPE   mechType,
        CK_BYTE_PTR         pbData,
        CK_ULONG            ulDataLen
    );

#define DIGEST(mech, pbData, ulDataLen) mscapi::Digest(mech, pbData, ulDataLen)
#define DIGEST_SHA1(pbData, ulDataLen) DIGEST(CKM_SHA_1, pbData, ulDataLen)
#define DIGEST_SHA256(pbData, ulDataLen) DIGEST(CKM_SHA256, pbData, ulDataLen)
#define DIGEST_SHA384(pbData, ulDataLen) DIGEST(CKM_SHA384, pbData, ulDataLen)
#define DIGEST_SHA512(pbData, ulDataLen) DIGEST(CKM_SHA512, pbData, ulDataLen)

    /**
    * Sign/Verify
    */
    class CryptoSign : public core::CryptoSign {
    public:
        CryptoSign(
            CK_BBOOL type
        ) : core::CryptoSign(type)
        {}
    };
    /**
     * Sign/Verify
     */
    class RsaPKCS1Sign : public CryptoSign {
    public:
        RsaPKCS1Sign(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
            Scoped<core::Object>    key          /* signature key */
        );

        CK_RV Update(
            CK_BYTE_PTR       pPart,     /* the data to sign/verify */
            CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );

        /**
         * C_SignFinal finishes a multiple-part signature operation,
         * returning the signature.
         */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,      /* gets the signature */
            CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );

        /**
         * C_VerifyFinal finishes a multiple-part verification
         * operation, checking the signature.
         */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,     /* signature to verify */
            CK_ULONG          ulSignatureLen  /* signature length */
        );

    protected:
        Scoped<CryptoDigest> digest;
        LPCWSTR              digestAlgorithm;
        crypt::Hash          cDigest;
        Scoped<CryptoKey>    key;
    };

    /**
    * Sign/Verify
    */
    class RsaPSSSign : public CryptoSign {
    public:
        RsaPSSSign(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
            Scoped<core::Object>    key          /* signature key */
        );

        CK_RV Update(
            CK_BYTE_PTR       pPart,     /* the data to sign/verify */
            CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );

        /**
        * C_SignFinal finishes a multiple-part signature operation,
        * returning the signature.
        */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,      /* gets the signature */
            CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );

        /**
        * C_VerifyFinal finishes a multiple-part verification
        * operation, checking the signature.
        */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,     /* signature to verify */
            CK_ULONG          ulSignatureLen  /* signature length */
        );

    protected:
        Scoped<CryptoDigest> digest;
        LPCWSTR              digestAlgorithm;
        ULONG                salt;
        Scoped<CryptoKey>    key;
    };

    /**
    * Sign/Verify
    */
    class EcDSASign : public CryptoSign {
    public:
        EcDSASign(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
            Scoped<core::Object>    key          /* signature key */
        );

        CK_RV Update(
            CK_BYTE_PTR       pPart,     /* the data to sign/verify */
            CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );

        /**
        * C_SignFinal finishes a multiple-part signature operation,
        * returning the signature.
        */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,      /* gets the signature */
            CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );

        /**
        * C_VerifyFinal finishes a multiple-part verification
        * operation, checking the signature.
        */
        CK_RV Final(
            CK_BYTE_PTR       pSignature,     /* signature to verify */
            CK_ULONG          ulSignatureLen  /* signature length */
        );

    protected:
        Scoped<CryptoDigest> digest;
        Scoped<CryptoKey>  key;
    };

    class CryptoEncrypt : public core::CryptoEncrypt {
    public:
        CryptoEncrypt(
            CK_BBOOL type
        ) : core::CryptoEncrypt(type)
        {}
    };

    class CryptoRsaOAEPEncrypt : public CryptoEncrypt {
    public:
        CryptoRsaOAEPEncrypt(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR  pMechanism,
            Scoped<core::Object>    hKey
        );

        CK_RV Once
        (
            CK_BYTE_PTR       pData,
            CK_ULONG          ulDataLen,
            CK_BYTE_PTR       pEncryptedData,
            CK_ULONG_PTR      pulEncryptedDataLen
        );

        CK_RV Update
        (
            CK_BYTE_PTR       pPart,
            CK_ULONG          ulPartLen,
            CK_BYTE_PTR       pEncryptedPart,
            CK_ULONG_PTR      pulEncryptedPartLen
        );

        CK_RV Final
        (
            CK_BYTE_PTR       pLastEncryptedPart,
            CK_ULONG_PTR      pulLastEncryptedPartLen
        );

    protected:
        Scoped<CryptoKey>    key;
        LPWSTR               digestAlg;
    };

}