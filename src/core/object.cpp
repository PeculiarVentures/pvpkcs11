#include "object.h"

using namespace core;

Object::Object()
{
}

Object::~Object()
{
}

CK_RV Object::GetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	CHECK_ARGUMENT_NULL(pTemplate);

	CK_RV res = CKR_OK;

	for (size_t i = 0; i < ulCount && res == CKR_OK; i++) {
		CK_ATTRIBUTE_PTR attr = &pTemplate[i];

		switch (attr->type) {
		case CKA_CLASS:
			res = GetClass((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = CKR_ATTRIBUTE_TYPE_INVALID;
		}
	}

	return res;
}

CK_RV Object::SetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	CHECK_ARGUMENT_NULL(pTemplate);
	if (ulCount < 1) {
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Object::GetBool(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_BBOOL bValue)
{
	CK_ULONG valueLen = 1 * sizeof(CK_BBOOL);
	if (pValue) {
		if (valueLen > *pulValueLen) {
			return CKR_BUFFER_TOO_SMALL;
		}
		memcpy(pValue, &bValue, valueLen);
	}
	*pulValueLen = valueLen;

	return CKR_OK;
}

CK_RV Object::GetNumber(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_ULONG ulValue)
{
	CK_ULONG valueLen = 1 * sizeof(CK_ULONG);
	if (pValue) {
		if (valueLen > *pulValueLen) {
			return CKR_BUFFER_TOO_SMALL;
		}
		memcpy(pValue, &ulValue, valueLen);
	}
	*pulValueLen = valueLen;

	return CKR_OK;
}

CK_RV Object::GetUtf8String(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_UTF8CHAR_PTR pData, CK_ULONG ulDataLen)
{
	return this->GetBytes(pValue, pulValueLen, pData, ulDataLen);
}

CK_RV Object::GetBytes(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, CK_BYTE_PTR pData, CK_ULONG ulDataLen)
{
	CK_ULONG valueLen = ulDataLen * sizeof(CK_BYTE);
	if (pValue) {
		if (valueLen > *pulValueLen) {
			return CKR_BUFFER_TOO_SMALL;
		}
		memcpy(pValue, pData, ulDataLen);
	}
	*pulValueLen = valueLen;

	return CKR_OK;
}

CK_RV Object::GetBytes(CK_BYTE_PTR pValue, CK_ULONG_PTR pulValueLen, std::string* strBuffer)
{
	return GetBytes(pValue, pulValueLen, (BYTE*)strBuffer->c_str(), strBuffer->length());
}
