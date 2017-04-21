#pragma once

#include "../core/objects/rsa_public_key.h"
#include "crypt/crypt.h"

class MscapiRsaPublicKey : public RsaPublicKey {

public:
	
	MscapiRsaPublicKey(Scoped<crypt::Key> key, CK_BBOOL token);
	~MscapiRsaPublicKey();

	// Key
	DECLARE_GET_ATTRIBUTE(GetID);
	DECLARE_GET_ATTRIBUTE(GetStartDate);
	DECLARE_GET_ATTRIBUTE(GetEndDate);
	DECLARE_GET_ATTRIBUTE(GetDerive);
	DECLARE_GET_ATTRIBUTE(GetLocal);
	DECLARE_GET_ATTRIBUTE(GetKeyGenMechanism);
	DECLARE_GET_ATTRIBUTE(GetAllowedMechanisms);

	// Public key
	DECLARE_GET_ATTRIBUTE(GetSubject);
	DECLARE_GET_ATTRIBUTE(GetEncrypt);
	DECLARE_GET_ATTRIBUTE(GetVerify);
	DECLARE_GET_ATTRIBUTE(GetVerifyRecover);
	DECLARE_GET_ATTRIBUTE(GetWrap);
	DECLARE_GET_ATTRIBUTE(GetTrusted);
	DECLARE_GET_ATTRIBUTE(GetWrapTemplate);

	// Rsa
	DECLARE_GET_ATTRIBUTE(GetModulus);
	DECLARE_GET_ATTRIBUTE(GetModulusBits);
	DECLARE_GET_ATTRIBUTE(GetPublicExponent);

	Scoped<crypt::Key> value;
	std::string id;
};