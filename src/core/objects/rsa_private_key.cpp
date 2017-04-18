#include "rsa_private_key.h"

CK_RV RsaPrivateKey::GetAttributeValue
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
		case CKA_PUBLIC_EXPONENT:
			res = GetPublicExponent((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_PRIVATE_EXPONENT:
			res = GetPrivateExponent((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_PRIME_1:
			res = GetPrime1((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_PRIME_2:
			res = GetPrime2((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_EXPONENT_1:
			res = GetExponent1((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_EXPONENT_2:
			res = GetExponent2((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		case CKA_COEFFICIENT:
			res = GetCoefficient((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
			break;
		default:
			res = PrivateKey::GetAttributeValue(attr, 1);
		}
	}

	return res;
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetModulus)
{
	return CKR_ATTRIBUTE_TYPE_INVALID;
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPublicExponent)
{
	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	CK_RV res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->qi.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrivateExponent)
{
	// TODO: Move checking for Private functionality to Method
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->d.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrime1)
{
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->p.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetPrime2)
{
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->q.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetExponent1)
{
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->dp.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetExponent2)
{
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->dq.length());
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetCoefficient)
{
	CK_BBOOL bbExtractable;
	CK_ULONG ulExtractableLen = sizeof(CK_BBOOL);
	CK_RV res = this->GetExtractable((CK_BYTE_PTR)&bbExtractable, &ulExtractableLen);
	if (res != CKR_OK) {
		return res;
	}
	if (bbExtractable) {
		return CKR_ATTRIBUTE_SENSITIVE;
	}

	Scoped<RsaPrivateKeyStruct> key(new RsaPrivateKeyStruct);
	res = this->GetKeyStruct(key.get());
	if (res != CKR_OK) {
		return res;
	}

	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)key->qi.c_str(), key->qi.length());
}

CK_RV RsaPrivateKey::GetKeyStruct(RsaPrivateKeyStruct* rsaKey)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

DECLARE_GET_ATTRIBUTE(RsaPrivateKey::GetKeyType)
{
	return this->GetNumber(pValue, pulValueLen, CKK_RSA);
}