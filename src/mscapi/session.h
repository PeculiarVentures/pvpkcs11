#pragma once

#include "../core/session.h"

namespace mscapi {

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

	protected:
		void LoadMyStore();
	};

}