#pragma once
#include "../pkcs11.h"
#include "object.h"
#include "crypto.h"
#include "collection.h"

#ifdef GetObject
#undef GetObject
#endif

namespace core {

    typedef struct OBJECT_FIND
    {
        bool active;
        CK_ATTRIBUTE_PTR pTemplate;
        CK_ULONG ulTemplateSize;
        CK_ULONG index;
    } OBJECT_FIND;

    class Session
    {
    public:
        CK_SLOT_ID SlotID;

        CK_SESSION_HANDLE     Handle;
        bool                  ReadOnly;
        CK_VOID_PTR           Application;
        CK_NOTIFY             Notify;

        // Info
        CK_STATE              State;
        CK_FLAGS              Flags;          /* see below */
        CK_ULONG              DeviceError;  /* device-dependent error code */

        Scoped<CryptoDigest>  digest;
        Scoped<CryptoSign>    sign;
        Scoped<CryptoSign>    verify;
        Scoped<CryptoEncrypt> encrypt;
        Scoped<CryptoEncrypt> decrypt;

        Collection<Scoped<Object> > objects;

        // find
        OBJECT_FIND           find;

        Session();
        ~Session();

        CK_RV InitPIN
        (
            CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
            CK_ULONG          ulPinLen   /* length in bytes of the PIN */
        );

        virtual CK_RV Open
        (
            CK_FLAGS              flags,         /* from CK_SESSION_INFO */
            CK_VOID_PTR           pApplication,  /* passed to callback */
            CK_NOTIFY             Notify,        /* callback function */
            CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
        );

        virtual CK_RV Close();

        CK_RV GetInfo
        (
            CK_SESSION_INFO_PTR pInfo      /* receives session info */
        );

        CK_RV Login
        (
            CK_USER_TYPE      userType,  /* the user type */
            CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
            CK_ULONG          ulPinLen   /* the length of the PIN */
        );

        /* Object management */

        virtual CK_RV GetAttributeValue
        (
            CK_OBJECT_HANDLE  hObject,    /* the object's handle */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV SetAttributeValue
        (
            CK_OBJECT_HANDLE  hObject,    /* the object's handle */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
            CK_ULONG          ulCount     /* attributes in template */
        );

        virtual CK_RV FindObjectsInit
        (
            CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
            CK_ULONG          ulCount     /* attributes in search template */
        );

        virtual CK_RV FindObjects
        (
            CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
            CK_ULONG             ulMaxObjectCount,  /* max handles to get */
            CK_ULONG_PTR         pulObjectCount     /* actual # returned */
        );

        virtual CK_RV FindObjectsFinal();

        /**
         * C_SeedRandom mixes additional seed material into the token's
         * random number generator.
         */
        virtual CK_RV SeedRandom(
            CK_BYTE_PTR       pSeed,     /* the seed material */
            CK_ULONG          ulSeedLen  /* length of seed material */
        );

        /* C_GenerateRandom generates random data. */
        virtual CK_RV GenerateRandom(
            CK_BYTE_PTR       RandomData,  /* receives the random data */
            CK_ULONG          ulRandomLen  /* # of bytes to generate */
        );

        // Message verification

        /**
         * Initializes verify object
         * - check pMechanism is NULLs
         * - check type for pMechanism->mechanism (CKF_VERIFY)
         * - check hKey is NULL
         */
        virtual CK_RV VerifyInit(
            CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
            CK_OBJECT_HANDLE  hKey         /* verification key */
        );

        // Message signing

        /**
        * Initializes sign object
        * - check pMechanism is NULLs
        * - check type for pMechanism->mechanism (CKF_SIGN)
        * - check hKey is NULL
        */
        virtual CK_RV SignInit(
            CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of signature key */
        );

        /* Encryption and decryption */

        virtual CK_RV EncryptInit
        (
            CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
        );

        virtual CK_RV DecryptInit
        (
            CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
            CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
        );

        // Key generation

        virtual CK_RV GenerateKey
        (
            CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
            CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
            CK_ULONG             ulCount,     /* # of attrs in template */
            CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
        );

        virtual CK_RV GenerateKeyPair
        (
            CK_MECHANISM_PTR     pMechanism,                  /* key-gen mechanism */
            CK_ATTRIBUTE_PTR     pPublicKeyTemplate,          /* template for pub. key */
            CK_ULONG             ulPublicKeyAttributeCount,   /* # pub. attributes */
            CK_ATTRIBUTE_PTR     pPrivateKeyTemplate,         /* template for private key */
            CK_ULONG             ulPrivateKeyAttributeCount,  /* # private attributes */
            CK_OBJECT_HANDLE_PTR phPublicKey,                 /* gets pub. key handle */
            CK_OBJECT_HANDLE_PTR phPrivateKey                 /* gets private key handle */
        );

        /**
         * C_DeriveKey derives a key from a base key, creating a new key
         * object.
         */
        virtual CK_RV DeriveKey
        (
            CK_MECHANISM_PTR     pMechanism,        /* key derivation mechanism */
            CK_OBJECT_HANDLE     hBaseKey,          /* base key */
            CK_ATTRIBUTE_PTR     pTemplate,         /* new key template */
            CK_ULONG             ulAttributeCount,  /* template length */
            CK_OBJECT_HANDLE_PTR phKey              /* gets new handle */
        );

        virtual Scoped<Object> CreateObject
        (
            CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
            CK_ULONG                ulCount      /* attributes in template */
        ) = 0;

        virtual Scoped<Object> CopyObject
        (
            Scoped<Object>       object,      /* the object for copying */
            CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
            CK_ULONG             ulCount      /* attributes in template */
        ) = 0;

        void CheckMechanismType(CK_MECHANISM_TYPE mechanism, CK_ULONG usage);
        virtual Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject);

    protected:

    };

}
