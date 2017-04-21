#pragma once

#include "../stdafx.h"
#include "../core/objects/rsa_private_key.h"
#include "crypt/crypt.h"

class MscapiRsaPrivateKey : public RsaPrivateKey {

public:
	Scoped<crypt::Key> value;

	std::string    id;

	MscapiRsaPrivateKey(Scoped<crypt::Key> key, CK_BBOOL token);
	~MscapiRsaPrivateKey();

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

	// Private
	DECLARE_GET_ATTRIBUTE(GetSubject);
	DECLARE_GET_ATTRIBUTE(GetSensitive);
	DECLARE_GET_ATTRIBUTE(GetDecrypt);
	DECLARE_GET_ATTRIBUTE(GetSign);
	DECLARE_GET_ATTRIBUTE(GetSignRecover);
	DECLARE_GET_ATTRIBUTE(GetUnwrap);
	DECLARE_GET_ATTRIBUTE(GetExtractable);
	DECLARE_GET_ATTRIBUTE(GetAlwaysSensitive);
	DECLARE_GET_ATTRIBUTE(GetNeverExtractable);
	DECLARE_GET_ATTRIBUTE(GetWrapWithTrusted);
	DECLARE_GET_ATTRIBUTE(GetUnwrapTemplate);
	DECLARE_GET_ATTRIBUTE(GetAlwaysAuthenticate);

	CK_RV GetKeyStruct(RsaPrivateKeyStruct* rsaKey);

};