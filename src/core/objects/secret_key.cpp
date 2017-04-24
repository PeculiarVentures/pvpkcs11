#include "secret_key.h"

CK_RV SecretKey::GetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	try {
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
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetClass)
{
	try {
		return this->GetNumber(pValue, pulValueLen, CKO_SECRET_KEY);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetSensitive)
{
	try {
		return this->GetBool(pValue, pulValueLen, propSensitive);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetEncrypt)
{
	try {
		return this->GetBool(pValue, pulValueLen, propEncrypt);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetDecrypt)
{
	try {
		return this->GetBool(pValue, pulValueLen, propDecrypt);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetSign)
{
	try {
		return this->GetBool(pValue, pulValueLen, propSign);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetVerify)
{
	try {
		return this->GetBool(pValue, pulValueLen, propVerify);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrap)
{
	try {
		return this->GetBool(pValue, pulValueLen, propWrap);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetUnwrap)
{
	try {
		return this->GetBool(pValue, pulValueLen, propUnwrap);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetExtractable)
{
	try {
		return this->GetBool(pValue, pulValueLen, this->propExtractable);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetAlwaysSensitive)
{
	try {
		return this->GetBool(pValue, pulValueLen, propAlwaysSensitive);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetNeverExtractable)
{
	try {
		return this->GetBool(pValue, pulValueLen, propNeverExtractable);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetCheckValue)
{
	try {
		return this->GetBytes(pValue, pulValueLen, (BYTE*)propCheckValue.c_str(), propCheckValue.length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrapWithTrusted)
{
	try {
		return this->GetBool(pValue, pulValueLen, propWrapWithTrusted);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetTrusted)
{
	try {
		return this->GetBool(pValue, pulValueLen, propTrusted);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetWrapTemplate)
{
	try {
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(SecretKey::GetUnwrapTemplate)
{
	try {
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}
	CATCH_EXCEPTION;
}
