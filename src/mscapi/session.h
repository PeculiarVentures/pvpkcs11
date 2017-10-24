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

        CK_RV Open
        (
            CK_FLAGS              flags,         /* from CK_SESSION_INFO */
            CK_VOID_PTR           pApplication,  /* passed to callback */
            CK_NOTIFY             Notify,        /* callback function */
            CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
        );

        CK_RV Close();

        // Key generation

        CK_RV GenerateKey
        (
            CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
            CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
            CK_ULONG             ulCount,     /* # of attrs in template */
            CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
        );

        CK_RV GenerateKeyPair
        (
            CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
            CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
            CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
            CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
            CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
            CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
            CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
        );

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

        Scoped<core::Object> CreateObject
        (
            CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
            CK_ULONG                ulCount      /* attributes in template */
        );

        Scoped<core::Object> CopyObject
        (
            Scoped<core::Object> object,      /* the object for copying */
            CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
            CK_ULONG             ulCount      /* attributes in template */
        );

    protected:
        CertificateStorageList certStores;

        void LoadMyStore();
        void LoadRequestStore();
        void LoadCngKeys();
    };

}