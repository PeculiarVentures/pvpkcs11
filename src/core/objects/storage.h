#pragma once

#include "../object.h"

class Storage : public Object
{
public:
	Storage();
	~Storage();

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

	virtual DECLARE_GET_ATTRIBUTE(GetToken);
	virtual DECLARE_GET_ATTRIBUTE(GetPrivate);
	virtual DECLARE_GET_ATTRIBUTE(GetModifiable);
	virtual DECLARE_GET_ATTRIBUTE(GetLabel);
	virtual DECLARE_GET_ATTRIBUTE(GetCopyable);

protected:
	CK_BBOOL            propToken;
	CK_BBOOL            propPrivate;
	CK_BBOOL            propModifiable;
	Scoped<std::string> propLabel;
	CK_BBOOL            propCopyable;
};

