#include "../stdafx.h"
#include "session.h"
#include "objects/key.h"
#include "objects/public_key.h"
#include "object.h"

static CK_ATTRIBUTE_PTR ATTRIBUTE_new()
{
	CK_ATTRIBUTE_PTR attr = (CK_ATTRIBUTE*)malloc(sizeof(CK_ATTRIBUTE));
	attr->type = 0;
	attr->pValue = NULL_PTR;
	attr->ulValueLen = 0;
}

static void ATTRIBUTE_free(CK_ATTRIBUTE_PTR attr)
{
	if (attr) {
		if (attr->pValue) {
			free(attr->pValue);
			attr->pValue = NULL;
		}
		free(attr);
		attr = NULL;
	}
}

static void ATTRIBUTE_set_value(CK_ATTRIBUTE* attr, CK_VOID_PTR pbValue, CK_ULONG ulValueLen)
{
	if (pbValue && ulValueLen) {
		attr->pValue = (CK_VOID_PTR)malloc(ulValueLen);
		memcpy(attr->pValue, pbValue, ulValueLen);
	}
}

static void ATTRIBUTE_copy(CK_ATTRIBUTE* attrDst, CK_ATTRIBUTE* attrSrc)
{
	attrDst->type = attrSrc->type;
	attrDst->ulValueLen = attrSrc->ulValueLen;
	ATTRIBUTE_set_value(attrDst, attrSrc->pValue, attrSrc->ulValueLen);
}

#define CHECK_DIGEST_OPERATION()							\
	if (!this->digestInitialized) {							\
		return CKR_OPERATION_NOT_INITIALIZED;				\
	}

#define CHECK_MECHANISM_TYPE(mechanismType, usage)                          \
{                                                                           \
	CK_RV __res = this->CheckMechanismType(mechanismType, usage);           \
	if (__res != CKR_OK) {                                                  \
		return __res;                                                       \
	}                                                                       \
}

Session::Session()
{
	this->Handle = 0;
	this->ReadOnly = true;
	this->Application = NULL_PTR;
	this->Notify = NULL_PTR;

	this->find = {
		false, NULL_PTR, 0, 0
	};
	this->signInitialized = false;
	this->verifyInitialized = false;
	this->digestInitialized = false;
}

Session::~Session()
{
}

CK_RV Session::InitPIN
(
	CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::OpenSession
(
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	CHECK_ARGUMENT_NULL(phSession);
	// the CKF_SERIAL_SESSION bit must always be set
	if (!(flags & CKF_SERIAL_SESSION)) {
		// if a call to C_OpenSession does not have this bit set, 
		// the call should return unsuccessfully with the error code CKR_SESSION_PARALLEL_NOT_SUPPORTED
		return CKR_SESSION_PARALLEL_NOT_SUPPORTED;
	}

	this->ReadOnly = !!(flags & CKF_RW_SESSION);
	this->Application = pApplication;
	this->Notify = Notify;
	this->Handle = reinterpret_cast<CK_SESSION_HANDLE>(this);
	*phSession = this->Handle;

	// Info
	this->Flags = flags;

	return CKR_OK;
}

CK_RV Session::CloseSession()
{
	return CKR_OK;
}

CK_RV Session::GetSessionInfo
(
	CK_SESSION_INFO_PTR pInfo      /* receives session info */
)
{
	CHECK_ARGUMENT_NULL(pInfo);

	pInfo->slotID = this->SlotID;
	pInfo->flags = this->Flags;
	pInfo->state = 0;
	pInfo->ulDeviceError = 0;

	return CKR_OK;
}

CK_RV Session::C_Login
(
	CK_USER_TYPE      userType,  /* the user type */
	CK_UTF8CHAR_PTR   pPin,      /* the user's PIN */
	CK_ULONG          ulPinLen   /* the length of the PIN */
)
{
	switch (userType) {
	case CKU_USER:
	case CKU_SO:
	case CKU_CONTEXT_SPECIFIC:
		break;
	default:
		return CKR_ARGUMENTS_BAD;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::GetAttributeValue
(
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	Scoped<Object> object = this->GetObject(hObject);

	if (!object) {
		return CKR_OBJECT_HANDLE_INVALID;
	}

	return object->GetAttributeValue(pTemplate, ulCount);
}

CK_RV Session::SetAttributeValue
(
	CK_OBJECT_HANDLE  hObject,    /* the object's handle */
	CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
	CK_ULONG          ulCount     /* attributes in template */
)
{
	Scoped<Object> object = this->GetObject(hObject);

	if (!object) {
		return CKR_OBJECT_HANDLE_INVALID;
	}

	return object->SetAttributeValue(pTemplate, ulCount);
}

Scoped<Object> GetObject(CK_OBJECT_HANDLE hObject) {
	return NULL_PTR;
}

CK_RV Session::FindObjectsInit
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
	CK_ULONG          ulCount     /* attributes in search template */
)
{
	if (this->find.active) {
		return CKR_OPERATION_ACTIVE;
	}
	this->find.active = true;
	// copy template
	this->find.pTemplate = (CK_ATTRIBUTE_PTR)malloc(sizeof(CK_ATTRIBUTE) * ulCount);
	for (int i = 0; i < ulCount; i++) {
		this->find.pTemplate[i];
		ATTRIBUTE_copy(&this->find.pTemplate[i], &pTemplate[i]);
	}
	this->find.ulTemplateSize = ulCount;
	this->find.index = 0;

	return CKR_OK;
}

CK_RV Session::FindObjects
(
	CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
	CK_ULONG             ulMaxObjectCount,  /* max handles to get */
	CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	if (!this->find.active) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}
	CHECK_ARGUMENT_NULL(phObject);
	CHECK_ARGUMENT_NULL(pulObjectCount);
	if (ulMaxObjectCount < 0) {
		return CKR_ARGUMENTS_BAD;
	}

	*pulObjectCount = 0;

	return CKR_OK;
}

CK_RV Session::FindObjectsFinal()
{
	if (!this->find.active) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	// destroy Template
	if (this->find.pTemplate) {
		for (int i = 0; i < this->find.ulTemplateSize; i++) {
			if (this->find.pTemplate[i].pValue) {
				free(this->find.pTemplate[i].pValue);
			}
		}
		free(this->find.pTemplate);
	}
	this->find.pTemplate = NULL;
	this->find.ulTemplateSize = 0;
	this->find.active = false;
	this->find.index = 0;

	return CKR_OK;
}

CK_RV Session::DigestInit
(
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	CHECK_ARGUMENT_NULL(pMechanism);
	CHECK_MECHANISM_TYPE(pMechanism->mechanism, CKF_DIGEST);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::Digest
(
	CK_BYTE_PTR       pData,        /* data to be digested */
	CK_ULONG          ulDataLen,    /* bytes of data to digest */
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets digest length */
)
{
	CK_RV res = DigestUpdate(pData, ulDataLen);
	if (res != CKR_OK) {
		return res;
	}
	res = DigestFinal(pDigest, pulDigestLen);

	return res;
}

CK_RV Session::DigestUpdate
(
	CK_BYTE_PTR       pPart,     /* data to be digested */
	CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	CHECK_DIGEST_OPERATION();

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::DigestKey
(
	CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::DigestFinal
(
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	CHECK_DIGEST_OPERATION();
	CHECK_ARGUMENT_NULL(pDigest);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::CheckMechanismType(CK_MECHANISM_TYPE mechanism, CK_ULONG usage)
{
	CK_ULONG ulMechanismCount;
	CK_RV res = C_GetMechanismList(this->SlotID, NULL_PTR, &ulMechanismCount);
	if (res != CKR_OK) {
		return res;
	}

	bool found = false;
	CK_MECHANISM_TYPE_PTR mechanisms = static_cast<CK_MECHANISM_TYPE_PTR>(malloc(ulMechanismCount * sizeof(CK_MECHANISM_TYPE)));
	res = C_GetMechanismList(this->SlotID, mechanisms, &ulMechanismCount);
	if (res != CKR_OK) {
		return res;
	}
	for (size_t i = 0; i < ulMechanismCount; i++) {
		if (mechanisms[i] == mechanism) {
			CK_MECHANISM_INFO info;
			// check mechanism usage
			res = C_GetMechanismInfo(this->SlotID, mechanism, &info);
			if (res != CKR_OK) {
				return res;
			}
			else {
				if (info.flags & usage) {
					found = true;
				}
				break;
			}
		}
	}
	free(mechanisms);

	return found ? CKR_OK : CKR_MECHANISM_INVALID;
}

CK_RV Session::VerifyInit(
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	CK_RV res;
	if (this->verifyInitialized) {
		return CKR_OPERATION_ACTIVE;
	}
	CHECK_ARGUMENT_NULL(pMechanism);
	CHECK_MECHANISM_TYPE(pMechanism->mechanism, CKF_VERIFY);
	CHECK_ARGUMENT_NULL(hKey);
	Scoped<Object> object = this->GetObject(hKey);

	if (!object) {
		return CKR_OBJECT_HANDLE_INVALID;
	}
	Key* key;
	if (key = dynamic_cast<Key*>(object.get())) {
		// Check type of Key
		CK_ULONG ulKeyType;
		CK_ULONG ulKeyTypeLen = sizeof(CK_ULONG);
		res = key->GetClass((CK_BYTE_PTR)&ulKeyType, &ulKeyTypeLen);
		if (res != CKR_OK) {
			return CKR_FUNCTION_FAILED;
		}
		if (!(ulKeyType == CKO_PUBLIC_KEY || ulKeyType == CKO_SECRET_KEY)) {
			return CKR_KEY_TYPE_INCONSISTENT;
		}
	}
	else {
		return CKR_KEY_HANDLE_INVALID;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::Verify(
	CK_BYTE_PTR       pData,          /* signed data */
	CK_ULONG          ulDataLen,      /* length of signed data */
	CK_BYTE_PTR       pSignature,     /* signature */
	CK_ULONG          ulSignatureLen  /* signature length*/
)
{
	CK_RV res = VerifyUpdate(pData, ulDataLen);
	if (res != CKR_OK) {
		return res;
	}
	res = VerifyFinal(pSignature, ulSignatureLen);

	return res;
}

CK_RV Session::VerifyUpdate(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	if (!this->verifyInitialized) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::VerifyFinal(
	CK_BYTE_PTR       pSignature,     /* signature to verify */
	CK_ULONG          ulSignatureLen  /* signature length */
)
{
	if (!this->verifyInitialized) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::SignInit(
	CK_MECHANISM_PTR  pMechanism,  /* the signature mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of signature key */
)
{
	CK_RV res;
	if (this->signInitialized) {
		return CKR_OPERATION_ACTIVE;
	}
	CHECK_ARGUMENT_NULL(pMechanism);
	CHECK_MECHANISM_TYPE(pMechanism->mechanism, CKF_SIGN);
	CHECK_ARGUMENT_NULL(hKey);
	Scoped<Object> object = this->GetObject(hKey);

	if (!object) {
		return CKR_OBJECT_HANDLE_INVALID;
	}
	Key* key;
	if (key = dynamic_cast<Key*>(object.get())) {
		// Check type of Key
		CK_ULONG ulKeyType;
		CK_ULONG ulKeyTypeLen = sizeof(CK_ULONG);
		res = key->GetClass((CK_BYTE_PTR)&ulKeyType, &ulKeyTypeLen);
		if (res != CKR_OK) {
			return CKR_FUNCTION_FAILED;
		}
		if (!(ulKeyType == CKO_PRIVATE_KEY || ulKeyType == CKO_SECRET_KEY)) {
			return CKR_KEY_TYPE_INCONSISTENT;
		}
	}
	else {
		return CKR_KEY_HANDLE_INVALID;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::Sign(
	CK_BYTE_PTR       pData,           /* the data to sign */
	CK_ULONG          ulDataLen,       /* count of bytes to sign */
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	CK_RV res = SignUpdate(pData, ulDataLen);
	if (res != CKR_OK) {
		return res;
	}
	res = SignFinal(pSignature, pulSignatureLen);

	return res;
}

CK_RV Session::SignUpdate(
	CK_BYTE_PTR       pPart,     /* the data to sign */
	CK_ULONG          ulPartLen  /* count of bytes to sign */
)
{
	if (!this->signInitialized) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Session::SignFinal(
	CK_BYTE_PTR       pSignature,      /* gets the signature */
	CK_ULONG_PTR      pulSignatureLen  /* gets signature length */
)
{
	if (!this->signInitialized) {
		return CKR_OPERATION_NOT_INITIALIZED;
	}

	return CKR_FUNCTION_NOT_SUPPORTED;
}
