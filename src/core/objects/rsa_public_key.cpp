#include "rsa_public_key.h"

using namespace core;

CK_RV RsaPublicKey::GetAttributeValue
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
		case CKA_MODULUS:
			res = GetModulus((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_MODULUS_BITS:
			res = GetModulusBits((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_PUBLIC_EXPONENT:
			res = GetPublicExponent((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = PublicKey::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetModulus)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetModulusBits)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetPublicExponent)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(RsaPublicKey::GetKeyType)
{
	return this->GetNumber(pValue, pulValueLen, CKK_RSA);
}