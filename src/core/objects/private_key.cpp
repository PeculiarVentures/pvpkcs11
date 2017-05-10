#include "private_key.h"

using namespace core;

CK_RV PrivateKey::GetAttributeValue
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
		case CKA_SUBJECT:
			res = GetSubject((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SENSITIVE:
			res = GetSensitive((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_DECRYPT:
			res = GetDecrypt((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SIGN:
			res = GetSign((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SIGN_RECOVER:
			res = GetSignRecover((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
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
		case CKA_WRAP_WITH_TRUSTED:
			res = GetWrapWithTrusted((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_UNWRAP_TEMPLATE:
			res = GetUnwrapTemplate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_ALWAYS_AUTHENTICATE:
			res = GetAlwaysAuthenticate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = Key::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetClass)
{
	return this->GetNumber(pValue, pulValueLen, CKO_PRIVATE_KEY);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetSubject)
{
	return GetBytes(pValue, pulValueLen, &propSubject);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetSensitive)
{
	return GetBool(pValue, pulValueLen, propSensitive);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetDecrypt)
{
	return GetBool(pValue, pulValueLen, propDecrypt);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetSign)
{
	return GetBool(pValue, pulValueLen, propSign);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetSignRecover)
{
	return GetBool(pValue, pulValueLen, propSignRecover);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetUnwrap)
{
	return GetBool(pValue, pulValueLen, propUnwrap);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetExtractable)
{
	return GetBool(pValue, pulValueLen, propExtractable);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetAlwaysSensitive)
{
	return GetBool(pValue, pulValueLen, propAlwaysSensitive);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetNeverExtractable)
{
	return GetBool(pValue, pulValueLen, propNeverExtractable);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetWrapWithTrusted)
{
	return GetBool(pValue, pulValueLen, propWrapWithTrusted);
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetUnwrapTemplate)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(PrivateKey::GetAlwaysAuthenticate)
{
	return GetBool(pValue, pulValueLen, propAlwaysAuthenticate);
}
