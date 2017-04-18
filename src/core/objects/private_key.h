#pragma once

#include "../../stdafx.h"
#include "key.h"

class PrivateKey : public Key {

public:
	CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	DECLARE_GET_ATTRIBUTE(GetClass);

	virtual DECLARE_GET_ATTRIBUTE(GetSubject);
	virtual DECLARE_GET_ATTRIBUTE(GetSensitive);
	virtual DECLARE_GET_ATTRIBUTE(GetDecrypt);
	virtual DECLARE_GET_ATTRIBUTE(GetSign);
	virtual DECLARE_GET_ATTRIBUTE(GetSignRecover);
	virtual DECLARE_GET_ATTRIBUTE(GetUnwrap);
	virtual DECLARE_GET_ATTRIBUTE(GetExtractable);
	virtual DECLARE_GET_ATTRIBUTE(GetAlwaysSensitive);
	virtual DECLARE_GET_ATTRIBUTE(GetNeverExtractable);
	virtual DECLARE_GET_ATTRIBUTE(GetWrapWithTrusted);
	virtual DECLARE_GET_ATTRIBUTE(GetUnwrapTemplate);
	virtual DECLARE_GET_ATTRIBUTE(GetAlwaysAuthenticate);

};