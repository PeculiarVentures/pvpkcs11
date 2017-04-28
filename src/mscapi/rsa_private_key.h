#pragma once

#include "../stdafx.h"
#include "../core/objects/rsa_private_key.h"
#include "crypt/crypt.h"

class MscapiRsaPrivateKey : public RsaPrivateKey {

public:
	Scoped<crypt::Key> value;

	std::string    id;

	MscapiRsaPrivateKey() {};
	MscapiRsaPrivateKey(Scoped<crypt::Key> key, CK_BBOOL token);
	~MscapiRsaPrivateKey();

	CK_RV GetKeyStruct(RsaPrivateKeyStruct* rsaKey);

};