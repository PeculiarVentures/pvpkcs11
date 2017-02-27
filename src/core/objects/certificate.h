#pragma once

#include "storage.h"

#define CERTIFICATE_CHECK_VALUE_LENGTH 3

class Certificate : public Storage
{
public:
	Certificate();
	~Certificate();

	virtual CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	virtual CK_RV SetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	DECLARE_GET_ATTRIBUTE(GetClass);
	virtual DECLARE_GET_ATTRIBUTE(GetCertificateType);
	virtual DECLARE_GET_ATTRIBUTE(GetTrusted);
	virtual DECLARE_GET_ATTRIBUTE(GetCertificateCategory);
	virtual DECLARE_GET_ATTRIBUTE(GetCheckValue);
	virtual DECLARE_GET_ATTRIBUTE(GetStartDate);
	virtual DECLARE_GET_ATTRIBUTE(GetEndDate);

};

