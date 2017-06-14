#pragma once

#include "../stdafx.h"
#include "../core/crypto.h"
#include "aes.h"
#include "key.h"

#include "helper.h"

#include <CommonCrypto/CommonCrypto.h>

namespace osx {
    
    class CryptoDigest : public core::CryptoDigest {
    public:
        CK_MECHANISM_TYPE   mechType;
        
        CryptoDigest() : core::CryptoDigest() {}
        
        CK_RV Init
        (
         CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
        );
        
        CK_RV Update
        (
         CK_BYTE_PTR       pPart,     /* data to be digested */
         CK_ULONG          ulPartLen  /* bytes of data to be digested */
        );
        
        CK_RV Final
        (
         CK_BYTE_PTR       pDigest,      /* gets the message digest */
         CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
        );
        
    protected:
        
        CC_SHA1_CTX         sha1Alg;
        CC_SHA256_CTX       sha256Alg;
        CC_SHA512_CTX       sha512Alg;
        
        CK_ULONG GetDigestLength(
                                 CK_MECHANISM_TYPE   mechanism
                                 );
    };
    
    Scoped<Buffer> Digest(
                          CK_MECHANISM_TYPE   mechType,
                          CK_BYTE_PTR         pbData,
                          CK_ULONG            ulDataLen
                          );
    
#define DIGEST_SHA1(pbData, ulDataLen) mscapi::Digest(CKM_SHA_1, pbData, ulDataLen)
#define DIGEST_SHA256(pbData, ulDataLen) mscapi::Digest(CKM_SHA256, pbData, ulDataLen)
#define DIGEST_SHA384(pbData, ulDataLen) mscapi::Digest(CKM_SHA384, pbData, ulDataLen)
#define DIGEST_SHA512(pbData, ulDataLen) mscapi::Digest(CKM_SHA512, pbData, ulDataLen)
    
    class CryptoAesEncrypt : public core::CryptoEncrypt {
    public:
        CryptoAesEncrypt(CK_BBOOL type);
        
        CK_RV Init
        (
         CK_MECHANISM_PTR  pMechanism,
         Scoped<core::Object>    hKey
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
        CCCryptorRef        cryptor;
    };
    
    class CryptoAesGCMEncrypt : public core::CryptoEncrypt {
    public:
        CryptoAesGCMEncrypt(
                            CK_BBOOL type
                            );
        
        CK_RV Init
        (
         CK_MECHANISM_PTR        pMechanism,
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
        AesKey*                key;
        Scoped<std::string>    iv;
        Scoped<std::string>    aad;
        CK_ULONG               tagLength;
        CK_ULONG               blockLength;
    };
    
    class RsaPKCS1Sign : public core::CryptoSign {
    public:
        RsaPKCS1Sign(CK_BBOOL type);
        
        CK_RV Init
        (
         CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
         Scoped<core::Object>    key          /* signature key */
        );
        
        CK_RV Update
        (
         CK_BYTE_PTR       pPart,     /* the data to sign/verify */
         CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );
        
        /**
         * C_SignFinal finishes a multiple-part signature operation,
         * returning the signature.
         */
        CK_RV Final
        (
         CK_BYTE_PTR       pSignature,      /* gets the signature */
         CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );
        
        /**
         * C_VerifyFinal finishes a multiple-part verification
         * operation, checking the signature.
         */
        CK_RV Final
        (
         CK_BYTE_PTR       pSignature,     /* signature to verify */
         CK_ULONG          ulSignatureLen  /* signature length */
        );
        
    protected:
        CryptoDigest    digest;
        Key*            key;
    };
    
    class EcDsaSign : public core::CryptoSign {
    public:
        EcDsaSign(CK_BBOOL type);
        
        CK_RV Init
        (
         CK_MECHANISM_PTR        pMechanism,  /* the signature mechanism */
         Scoped<core::Object>    key          /* signature key */
        );
        
        CK_RV Update
        (
         CK_BYTE_PTR       pPart,     /* the data to sign/verify */
         CK_ULONG          ulPartLen  /* count of bytes to sign/verify */
        );
        
        /**
         * C_SignFinal finishes a multiple-part signature operation,
         * returning the signature.
         */
        CK_RV Final
        (
         CK_BYTE_PTR       pSignature,      /* gets the signature */
         CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
        );
        
        /**
         * C_VerifyFinal finishes a multiple-part verification
         * operation, checking the signature.
         */
        CK_RV Final
        (
         CK_BYTE_PTR       pSignature,     /* signature to verify */
         CK_ULONG          ulSignatureLen  /* signature length */
        );
        
    protected:
        CryptoDigest    digest;
        Key*            key;
    };
    
}
