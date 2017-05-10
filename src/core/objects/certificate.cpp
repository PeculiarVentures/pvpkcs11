#include "certificate.h"

using namespace core;

Certificate::Certificate()
{
}


Certificate::~Certificate()
{
}

CK_RV Certificate::GetAttributeValue
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
		case CKA_CERTIFICATE_TYPE:
			res = GetCertificateType((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_TRUSTED:
			res = GetTrusted((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_CERTIFICATE_CATEGORY:
			res = GetCertificateCategory((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_CHECK_VALUE:
			res = GetCheckValue((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_START_DATE:
			res = GetStartDate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_END_DATE:
			res = GetEndDate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = Storage::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

CK_RV Certificate::SetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	return Storage::SetAttributeValue(pTemplate, ulCount);
}

DECLARE_GET_ATTRIBUTE(Certificate::GetClass)
{
	return this->GetNumber(pValue, pulValueLen, CKO_CERTIFICATE);
}

DECLARE_GET_ATTRIBUTE(Certificate::GetCertificateType)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(Certificate::GetTrusted)
{
	return this->GetBool(pValue, pulValueLen, CK_FALSE);
}

DECLARE_GET_ATTRIBUTE(Certificate::GetCertificateCategory)
{
	return this->GetNumber(pValue, pulValueLen, 0); // unspecified
}

DECLARE_GET_ATTRIBUTE(Certificate::GetCheckValue)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(Certificate::GetStartDate)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(Certificate::GetEndDate)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}
