#pragma once

#include "../../stdafx.h"
#include "private_key.h"

struct RsaPrivateKeyStruct {
	std::string n;
	std::string e;
	std::string d;
	std::string p;
	std::string q;
	std::string dp;
	std::string dq;
	std::string qi;
};

class RsaPrivateKey : public PrivateKey {

public:
	CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	DECLARE_GET_ATTRIBUTE(GetKeyType);

	virtual DECLARE_GET_ATTRIBUTE(GetModulus);
	virtual DECLARE_GET_ATTRIBUTE(GetPublicExponent);
	virtual DECLARE_GET_ATTRIBUTE(GetPrivateExponent);
	virtual DECLARE_GET_ATTRIBUTE(GetPrime1);
	virtual DECLARE_GET_ATTRIBUTE(GetPrime2);
	virtual DECLARE_GET_ATTRIBUTE(GetExponent1);
	virtual DECLARE_GET_ATTRIBUTE(GetExponent2);
	virtual DECLARE_GET_ATTRIBUTE(GetCoefficient);

	virtual CK_RV GetKeyStruct(RsaPrivateKeyStruct* rsaKey);

};