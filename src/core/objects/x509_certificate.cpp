#include "x509_certificate.h"

using namespace core;

X509Certificate::X509Certificate()
{
}


X509Certificate::~X509Certificate()
{
}

CK_RV X509Certificate::GetAttributeValue
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
		case CKA_CERTIFICATE_TYPE:
			res = GetCertificateType((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SUBJECT:
			res = GetSubject((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_ID:
			res = GetID((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_ISSUER:
			res = GetIssuer((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_SERIAL_NUMBER:
			res = GetSerialNumber((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_VALUE:
			res = GetValue((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_URL:
			res = GetURL((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
			res = GetHashOfSubjectPublicKey((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
			res = GetHashOfIssuerPublicKey((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_JAVA_MIDP_SECURITY_DOMAIN:
			res = GetJavaMidpSecurityDomain((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_NAME_HASH_ALGORITHM:
			res = GetNameHashAlgorithm((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = Certificate::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

CK_RV X509Certificate::SetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	return Certificate::SetAttributeValue(pTemplate, ulCount);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetCertificateType)
{
	return this->GetNumber(pValue, pulValueLen, CKC_X_509);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetSubject)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetID)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetIssuer)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetSerialNumber)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetValue)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetURL)
{
	return this->GetUtf8String(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetHashOfSubjectPublicKey)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetHashOfIssuerPublicKey)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetJavaMidpSecurityDomain)
{
	return this->GetNumber(pValue, pulValueLen, 0); // unspecified
}

DECLARE_GET_ATTRIBUTE(X509Certificate::GetNameHashAlgorithm)
{
	return this->GetNumber(pValue, pulValueLen, CKM_SHA_1);;
}
