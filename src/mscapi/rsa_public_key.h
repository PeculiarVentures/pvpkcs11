#pragma once

#include "../core/objects/rsa_public_key.h"
#include "key.h";

class MscapiRsaPublicKey : public RsaPublicKey {

public:

	CK_BBOOL token;
	
	~MscapiRsaPublicKey();

	// Storage
	DECLARE_GET_ATTRIBUTE(GetToken);
	DECLARE_GET_ATTRIBUTE(GetPrivate);
	DECLARE_GET_ATTRIBUTE(GetModifiable);
	DECLARE_GET_ATTRIBUTE(GetLabel);
	DECLARE_GET_ATTRIBUTE(GetCopyable);

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

	Scoped<MscapiKey> key;
	std::string id;
};