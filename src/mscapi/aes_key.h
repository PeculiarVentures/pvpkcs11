#pragma once

#include "../core/objects/aes_key.h"
#include "crypt/crypt.h"

class MscapiAesKey: public AesKey {

public:
	Scoped<crypt::Key> value;

	static Scoped<Object> GenerateKey
	(
		CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
		CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
		CK_ULONG             ulCount     /* # of attrs in template */
	);

	MscapiAesKey();

	void SetCryptoKey(Scoped<crypt::Key> value);

	DECLARE_GET_ATTRIBUTE(GetValue);

};