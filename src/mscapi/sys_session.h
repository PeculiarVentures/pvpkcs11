#pragma once

#include "session.h"

namespace mscapi {

    class SystemSession : public Session
    {
    public:
        SystemSession();
        ~SystemSession();

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
        void LoadMyStore();
        void LoadRequestStore();
        void LoadCngKeys();
    };

}
