#include "aes_key.h"

using namespace core;

AesKey::AesKey() 
{
	propKeyType = CKK_AES;
}

CK_RV AesKey::GetAttributeValue
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
		case CKA_VALUE_LEN:
			res = GetValueLen((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_VALUE:
			res = GetValue((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = SecretKey::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

DECLARE_GET_ATTRIBUTE(AesKey::GetValueLen)
{
	if (!propValueLen) {
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	return this->GetNumber(pValue, pulValueLen, propValueLen);
}

DECLARE_GET_ATTRIBUTE(AesKey::GetValue)
{
	if (!propExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}
	return CKR_ATTRIBUTE_TYPE_INVALID;
}