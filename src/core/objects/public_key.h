#pragma once

#include "key.h"

class PublicKey : public Key {

public:
	CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	DECLARE_GET_ATTRIBUTE(GetClass);

	virtual DECLARE_GET_ATTRIBUTE(GetSubject);
	virtual DECLARE_GET_ATTRIBUTE(GetEncrypt);
	virtual DECLARE_GET_ATTRIBUTE(GetVerify);
	virtual DECLARE_GET_ATTRIBUTE(GetVerifyRecover);
	virtual DECLARE_GET_ATTRIBUTE(GetWrap);
	virtual DECLARE_GET_ATTRIBUTE(GetTrusted);
	virtual DECLARE_GET_ATTRIBUTE(GetWrapTemplate);

	std::string     propSubject;
	CK_BBOOL        propEncrypt;
	CK_BBOOL        propVerify;
	CK_BBOOL        propVerifyRecover;
	CK_BBOOL        propWrap;
	CK_BBOOL        propTrusted;
	// TODO GetWrapTemplate

};