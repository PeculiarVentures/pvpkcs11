#include "storage.h"

using namespace core;

Storage::Storage()
{
	this->handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
	this->propToken = false;
	this->propPrivate = false;
	this->propModifiable = false;
	this->propCopyable = false;
	this->propLabel = Scoped<std::string>(new std::string());
}


Storage::~Storage()
{
}

CK_RV Storage::GetAttributeValue
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
			case CKA_TOKEN:
				res = GetToken((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_PRIVATE:
				res = GetPrivate((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_MODIFIABLE:
				res = GetModifiable((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_LABEL:
				res = GetLabel((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			case CKA_COPYABLE:
				res = GetCopyable((CK_BYTE_PTR)attr->pValue, &attr->ulValueLen);
				break;
			default:
				res = Object::GetAttributeValue(attr, 1);
			}
		}

		return res;
	}
	CATCH_EXCEPTION;
}

CK_RV Storage::SetAttributeValue
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	try {
		return Object::GetAttributeValue(pTemplate, ulCount);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Storage::GetToken)
{
	try {
		return this->GetBool(pValue, pulValueLen, propToken);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Storage::GetPrivate)
{
	try {
		return this->GetBool(pValue, pulValueLen, propPrivate);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Storage::GetModifiable)
{
	try {
		return this->GetBool(pValue, pulValueLen, propModifiable);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Storage::GetLabel)
{
	try {
		return this->GetUtf8String(pValue, pulValueLen, (BYTE*)propLabel->c_str(), propLabel->length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(Storage::GetCopyable)
{
	try {
		return this->GetBool(pValue, pulValueLen, propCopyable);
	}
	CATCH_EXCEPTION;
}
