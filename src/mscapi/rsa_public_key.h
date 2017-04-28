#pragma once

#include "../core/objects/rsa_public_key.h"
#include "crypt/crypt.h"

class MscapiRsaPublicKey : public RsaPublicKey {

public:

	MscapiRsaPublicKey() {};
	MscapiRsaPublicKey(Scoped<crypt::Key> key, CK_BBOOL token);
	~MscapiRsaPublicKey();

	// Rsa
	DECLARE_GET_ATTRIBUTE(GetModulus);
	DECLARE_GET_ATTRIBUTE(GetModulusBits);
	DECLARE_GET_ATTRIBUTE(GetPublicExponent);

	Scoped<crypt::Key> value;
};