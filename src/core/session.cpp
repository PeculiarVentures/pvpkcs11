#include "../stdafx.h"
#include "session.h"

#define CHECK_DIGEST_OPERATION()							\
	if (!this->digestInitialized) {							\
		return CKR_OPERATION_NOT_INITIALIZED;				\
	}

#define CHECK_MECHANISM_TYPE(mechanismType)							\
{																	\
	CK_RV __res = this->CheckMechanismType(mechanismType);			\
	if (__res != CKR_OK) {											\
		return __res;												\
	}																\
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
	this->find.pTemplate = pTemplate;
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

	this->find.active = false;

	return CKR_OK;
}

CK_RV Session::DigestInit
(
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	CHECK_ARGUMENT_NULL(pMechanism);
	CHECK_MECHANISM_TYPE(pMechanism->mechanism);

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

CK_RV Session::CheckMechanismType(CK_MECHANISM_TYPE mechanism)
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
			found = true;
			break;
		}
	}
	free(mechanisms);

	return found ? CKR_OK : CKR_MECHANISM_INVALID;
}
