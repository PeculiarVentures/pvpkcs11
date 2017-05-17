#pragma once

#include "../stdafx.h"

#include "../core/objects/aes_key.h"
#include "key.h"
#include "ncrypt.h"
#include "crypto.h"

namespace mscapi {

    class AesKey : public core::AesKey, public CryptoKey {
    public:
        AesKey() :
            core::AesKey(),
            CryptoKey()
        {}

        static Scoped<core::SecretKey> Generate(
            CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
            Scoped<core::Template> tmpl
        );
    };

    class CryptoAesEncrypt : public CryptoEncrypt {
    public:
        CryptoAesEncrypt(
            CK_BBOOL type
        );

        CK_RV Init
        (
            CK_MECHANISM_PTR        pMechanism,
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
        CK_BBOOL                    padding;
        CK_ULONG                    mechanism;
        Scoped<bcrypt::Key>         key;
        Scoped<std::string>         iv;
        std::string                 buffer;
        ULONG                       blockLength;

        void Make(
            bool    bFinal,
            BYTE*   pbData,
            DWORD   dwDataLen,
            BYTE*   pbOut,
            DWORD*  pdwOutLen
        );
    };

    class CryptoAesGCMEncrypt : public CryptoEncrypt {
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
        Scoped<bcrypt::Key>			key;
        Scoped<std::string>         iv;
        Scoped<std::string>         aad;
        ULONG                       tagLength;
        ULONG                       blockLength;
    };

}