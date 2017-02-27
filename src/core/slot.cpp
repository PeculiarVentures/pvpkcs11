#include "../stdafx.h"
#include "slot.h"

#define CHECK_SESSION_HANDLE(hSession)                          \
	if (!this->hasSession(hSession)) {                          \
		return CKR_SESSION_HANDLE_INVALID;                      \
	}


Slot::Slot()
{
}

Slot::~Slot()
{
}

CK_RV Slot::GetSlotInfo(
	CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	CHECK_ARGUMENT_NULL(pInfo);

	SET_STRING(pInfo->slotDescription, (char*)(this->description), 64);
	SET_STRING(pInfo->manufacturerID, (char*)(this->manufacturerID), 32);
	pInfo->flags = this->flags;
	pInfo->hardwareVersion = this->hardwareVersion;
	pInfo->hardwareVersion = this->firmwareVersion;

	return CKR_OK;
}

CK_RV Slot::GetMechanismList
(
	CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
	CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	if (pMechanismList == NULL_PTR) {
		*pulCount = static_cast<CK_ULONG>(this->mechanisms.count());
	}
	else {
		if (*pulCount < this->mechanisms.count()) {
			return CKR_BUFFER_TOO_SMALL;
		}
		for (size_t i = 0; i < this->mechanisms.count(); i++) {
			pMechanismList[i] = this->mechanisms.items(i)->type;
		}
	}

	return CKR_OK;
}

CK_RV Slot::GetMechanismInfo
(
	CK_MECHANISM_TYPE     type,    /* type of mechanism */
	CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	if (!this->hasMechanism(type)) {
		return CKR_MECHANISM_INVALID;
	}
	CHECK_ARGUMENT_NULL(pInfo);

	for (size_t i = 0; i < this->mechanisms.count(); i++) {
		Scoped<Mechanism> mechanism = this->mechanisms.items(i);
		if (mechanism->type == type) {
			pInfo->flags = mechanism->flags;
			pInfo->ulMaxKeySize = mechanism->ulMaxKeySize;
			pInfo->ulMinKeySize = mechanism->ulMinKeySize;
		}
	}

	return CKR_OK;
}

bool Slot::hasMechanism(CK_MECHANISM_TYPE type) {
	for (size_t i = 0; i < this->mechanisms.count(); i++) {
		if (this->mechanisms.items(i)->type == type) {
			return true;
		}
	}
	return false;
}

bool Slot::hasSession(CK_SESSION_HANDLE hSession)
{
	for (size_t i = 0; i < this->sessions.count(); i++) {
		Scoped<Session> session = this->sessions.items(i);
		if (session->Handle == hSession) {
			return true;
		}
	}
}

CK_RV Slot::InitToken
(
	CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
	CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
	CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	CHECK_ARGUMENT_NULL(pLabel);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Slot::InitPIN
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	CHECK_SESSION_HANDLE(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV Slot::OpenSession
(
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	Scoped<Session> session = this->CreateSession();
	CK_RV res = session->OpenSession(flags, pApplication, Notify, phSession);
	if (res == CKR_OK) {
		session->SlotID = this->slotID;
		this->sessions.add(session);
	}
	return res;
}

CK_RV Slot::CloseSession
(
	CK_SESSION_HANDLE hSession  /* the session's handle */
)
{
	Scoped<Session> session = this->getSession(hSession);
	if (!session) {
		return CKR_SESSION_HANDLE_INVALID;
	}

	CK_RV res = session->CloseSession();
	if (res == CKR_OK) {
		this->sessions.remove(session);
	}

	return res;
}

Scoped<Session> Slot::getSession(CK_SESSION_HANDLE hSession)
{
	for (size_t i = 0; i < this->sessions.count(); i++) {
		Scoped<Session> session = this->sessions.items(i);
		if (session->Handle == hSession) {
			return session;
		}
	}
	return NULL_PTR;
}

CK_RV Slot::CloseAllSessions()
{
	while (this->sessions.count()) {
		Scoped<Session> session = this->sessions.items(0);

		this->CloseSession(session->Handle);
	}

	return CKR_OK;
}