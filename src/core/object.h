#pragma once

#include "../stdafx.h"
#include "excep.h"
#include "template.h"

/**
 * Get function for C_GetAttributeValue
 * template:
 * CK_RV <name>(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen)
 * pValue - value to be filled
 * pulValueLen - size of returned data
 */
#define DECLARE_GET_ATTRIBUTE(name)						\
	CK_RV name(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen)

class Object
{
public:

	CK_OBJECT_HANDLE handle;

	Object();
	~Object();

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

	virtual DECLARE_GET_ATTRIBUTE(GetClass) = NULL;

protected:
	CK_RV GetBool(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_BBOOL bValue);
	CK_RV GetNumber(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_ULONG ulValue);
	CK_RV GetUtf8String(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_UTF8CHAR_PTR pData, CK_ULONG ulDataLen);
	CK_RV GetBytes(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen);
	CK_RV GetBytes(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, std::string* strBuffer);
};

