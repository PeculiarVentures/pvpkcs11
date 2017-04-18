#pragma once

#include "../../stdafx.h"
#include "key.h"

class SecretKey : public Key {

public:
	CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	DECLARE_GET_ATTRIBUTE(GetClass);

	virtual DECLARE_GET_ATTRIBUTE(GetSensitive);
	virtual DECLARE_GET_ATTRIBUTE(GetEncrypt);
	virtual DECLARE_GET_ATTRIBUTE(GetDecrypt);
	virtual DECLARE_GET_ATTRIBUTE(GetSign);
	virtual DECLARE_GET_ATTRIBUTE(GetVerify);
	virtual DECLARE_GET_ATTRIBUTE(GetWrap);
	virtual DECLARE_GET_ATTRIBUTE(GetUnwrap);
	virtual DECLARE_GET_ATTRIBUTE(GetExtractable);
	virtual DECLARE_GET_ATTRIBUTE(GetAlwaysSensitive);
	virtual DECLARE_GET_ATTRIBUTE(GetNeverExtractable);
	virtual DECLARE_GET_ATTRIBUTE(GetCheckValue);
	virtual DECLARE_GET_ATTRIBUTE(GetWrapWithTrusted);
	virtual DECLARE_GET_ATTRIBUTE(GetTrusted);
	virtual DECLARE_GET_ATTRIBUTE(GetWrapTemplate);
	virtual DECLARE_GET_ATTRIBUTE(GetUnwrapTemplate);

};