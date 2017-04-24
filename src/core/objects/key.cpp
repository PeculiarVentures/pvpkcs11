#include "key.h"

Key::Key() :
	Storage()
{
	propId = std::string("");
	propDerive = false;
}

CK_RV Key::GetAttributeValue
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
			case CKA_KEY_TYPE:
				res = GetKeyType((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_ID:
				res = GetID((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_START_DATE:
				res = GetStartDate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_END_DATE:
				res = GetEndDate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_DERIVE:
				res = GetDerive((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_LOCAL:
				res = GetLocal((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_KEY_GEN_MECHANISM:
				res = GetEndDate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_ALLOWED_MECHANISMS:
				res = GetAllowedMechanisms((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			default:
				res = Storage::GetAttributeValue(attr, 1);
			}
		}

		return res;
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Key::GetKeyType)
{
	try {
		return this->GetNumber(pValue, pulValueLen, propKeyType);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Key::GetID)
{
	try {
		return this->GetBytes(pValue, pulValueLen, &propId);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Key::GetStartDate)
{
	THROW_PKCS11_ATTRIBUTE_TYPE_INVALID();
}

DECLARE_GET_ATTRIBUTE(Key::GetEndDate)
{
	THROW_PKCS11_ATTRIBUTE_TYPE_INVALID();
}

DECLARE_GET_ATTRIBUTE(Key::GetDerive)
{
	try {
		return this->GetBool(pValue, pulValueLen, propDerive);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Key::GetLocal)
{
	THROW_PKCS11_ATTRIBUTE_TYPE_INVALID();
}

DECLARE_GET_ATTRIBUTE(Key::GetKeyGenMechanism)
{
	THROW_PKCS11_ATTRIBUTE_TYPE_INVALID();
}

DECLARE_GET_ATTRIBUTE(Key::GetAllowedMechanisms)
{
	THROW_PKCS11_ATTRIBUTE_TYPE_INVALID();
}
