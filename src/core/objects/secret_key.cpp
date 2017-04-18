#include "secret_key.h"

CK_RV SecretKey::GetAttributeValue
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
		case CKA_SENSITIVE:
			res = GetSensitive((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_ENCRYPT:
			res = GetEncrypt((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_DECRYPT:
			res = GetDecrypt((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SIGN:
			res = GetSign((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_VERIFY:
			res = GetVerify((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_WRAP:
			res = GetWrap((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_UNWRAP:
			res = GetUnwrap((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_EXTRACTABLE:
			res = GetExtractable((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_ALWAYS_SENSITIVE:
			res = GetAlwaysSensitive((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_NEVER_EXTRACTABLE:
			res = GetNeverExtractable((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_CHECK_VALUE:
			res = GetCheckValue((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_WRAP_WITH_TRUSTED:
			res = GetWrapWithTrusted((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_TRUSTED:
			res = GetTrusted((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_WRAP_TEMPLATE:
			res = GetWrapTemplate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_UNWRAP_TEMPLATE:
			res = GetUnwrapTemplate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = Key::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetClass)
{
	return this->GetNumber(pValue, pulValueLen, CKO_SECRET_KEY);
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetSensitive)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetEncrypt)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetDecrypt)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetSign)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetVerify)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrap)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetUnwrap)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetExtractable)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetAlwaysSensitive)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetNeverExtractable)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetCheckValue)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrapWithTrusted)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetTrusted)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrapTemplate)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetUnwrapTemplate)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}
