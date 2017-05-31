#pragma once

#include "../stdafx.h"

#include "objects/secret_key.h"

namespace core {

    class CryptoDigest {
    public:
        CryptoDigest() : active(false) {

        }

        virtual CK_RV Init
        (
            CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
        );

        virtual CK_RV Once(
            CK_BYTE_PTR       pData,        /* data to be digested */
            CK_ULONG          ulDataLen,    /* bytes of data to digest */
            CK_BYTE_PTR       pDigest,      /* gets the message digest */
            CK_ULONG_PTR      pulDigestLen  /* gets digest length */
        );

        virtual CK_RV Update(
            CK_BYTE_PTR       pPart,     /* data to be digested */
            CK_ULONG          ulPartLen  /* bytes of data to be digested */
        );

        virtual CK_RV Key(
            Scoped<Object>    key        /* secret key to digest */
        );

        virtual CK_RV Final(
            CK_BYTE_PTR       pDigest,      /* gets the message digest */
            CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
        );
    protected:
        bool active;
    };

#define CRYPTO_SIGN    0
#define CRYPTO_VERIFY  1

    class CryptoSign {
    public:
        /**
         * type - CRYPTO_SIGN | CRYPTO_VERIFY
         */
        CryptoSign(
            CK_BBOOL type
        ) : active(false), type(type) {}

        virtual CK_RV Init
        (
            CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
            Scoped<Object>    key          /* signature key */
        );

        /**
         * Sign
         */
        virtual CK_RV Once(
            CK_BYTE_PTR       pData,           /* the data to sign */
            CK_ULONG          ulDataLen,       /* count of bytes to sign */
            CK_BYTE_PTR       pSignature,      /* gets the signature */
            CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );

        /**
         * Verify
         */
        virtual CK_RV Once(
            CK_BYTE_PTR       pData,           /* the data to sign */
            CK_ULONG          ulDataLen,       /* count of bytes to sign */
            CK_BYTE_PTR       pSignature,      /* signature to verify */
            CK_ULONG          ulSignatureLen   /* signature length */
        );

        virtual CK_RV Update(
            CK_BYTE_PTR       pPart,     /* the data to sign/verify */
            CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );

        /**
         * C_SignFinal finishes a multiple-part signature operation,
         * returning the signature.
         */
        virtual CK_RV Final(
            CK_BYTE_PTR       pSignature,      /* gets the signature */
            CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );

        /**
         * C_VerifyFinal finishes a multiple-part verification
         * operation, checking the signature.
         */
        virtual CK_RV Final(
            CK_BYTE_PTR       pSignature,     /* signature to verify */
            CK_ULONG          ulSignatureLen  /* signature length */
        );

        bool IsActive();

    protected:
        bool     active;
        CK_BBOOL type;
    };

#define CRYPTO_ENCRYPT      0
#define CRYPTO_DECRYPT      1

    class CryptoEncrypt {
    public:
        CryptoEncrypt(CK_BBOOL type);

        virtual CK_RV Init
        (
            CK_MECHANISM_PTR  pMechanism,
            Scoped<Object>    hKey
        );

        virtual CK_RV Once
        (
            CK_BYTE_PTR       pData,
            CK_ULONG          ulDataLen,
            CK_BYTE_PTR       pEncryptedData,
            CK_ULONG_PTR      pulEncryptedDataLen
        );

        virtual CK_RV Update
        (
            CK_BYTE_PTR       pPart,
            CK_ULONG          ulPartLen,
            CK_BYTE_PTR       pEncryptedPart,
            CK_ULONG_PTR      pulEncryptedPartLen
        );

        virtual CK_RV Final
        (
            CK_BYTE_PTR       pLastEncryptedPart,
            CK_ULONG_PTR      pulLastEncryptedPartLen
        );

        bool IsActive();

    protected:
        std::string label;
        bool        active;
        CK_BBOOL    type;
    };

}