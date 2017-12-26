#pragma once

#include "../core/session.h"
#include "crypt/cert_store.h"

namespace mscapi {

    using CertificateStorageList = SList<crypt::CertificateStorage>;

    class Session : public core::Session
    {
    public:
        Session();
        ~Session();

        /* C_GenerateRandom generates random data. */
        CK_RV GenerateRandom(
            CK_BYTE_PTR       RandomData,  /* receives the random data */
            CK_ULONG          ulRandomLen  /* # of bytes to generate */
        );

        // Message verifying

        CK_RV VerifyInit(
            CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
            CK_OBJECT_HANDLE  hKey         /* verification key */
        );

        // Message signing

        CK_RV SignInit(
            CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of signature key */
        );

        CK_RV EncryptInit
        (
            CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
        );

        CK_RV DecryptInit
        (
            CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
        );

        CK_RV DeriveKey
        (
            CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
            CK_OBJECT_HANDLE     hBaseKey,          /* base key */
            CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
            CK_ULONG             ulAttributeCount,  /* template length */
            CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
        );

    protected:
        CertificateStorageList certStores;
    };

}