#include "slot.h"

using namespace core;

#define CHECK_SESSION_HANDLE(hSession)                          \
	if (!this->hasSession(hSession)) {                          \
		return CKR_SESSION_HANDLE_INVALID;                      \
	}


core::Slot::Slot()
{
	this->tokenInfo = CK_TOKEN_INFO();
}

core::Slot::~Slot()
{
}

CK_RV core::Slot::GetSlotInfo(
	CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
)
{
	try {
		if (pInfo == NULL_PTR) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pInfo is NULL");
		}

		SET_STRING(pInfo->slotDescription, (char*)(this->description), 64);
		SET_STRING(pInfo->manufacturerID, (char*)(this->manufacturerID), 32);
		pInfo->flags = this->flags;
		pInfo->hardwareVersion = this->hardwareVersion;
		pInfo->firmwareVersion = this->firmwareVersion;

		return CKR_OK;
	}
	CATCH_EXCEPTION;
}

CK_RV core::Slot::GetTokenInfo
(
	CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
)
{
	try {
		if (pInfo == NULL_PTR) {
			THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pInfo is NULL");
		}

		// Copy data
		memcpy(pInfo, &this->tokenInfo, sizeof(CK_TOKEN_INFO));

		return CKR_OK;
	}
	CATCH_EXCEPTION;
}

CK_RV core::Slot::GetMechanismList
(
	CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
	CK_ULONG_PTR          pulCount         /* gets # of mechs. */
)
{
	try {
		if (pMechanismList == NULL_PTR) {
			*pulCount = static_cast<CK_ULONG>(this->mechanisms.count());
		}
		else {
			if (*pulCount < this->mechanisms.count()) {
				THROW_PKCS11_BUFFER_TOO_SMALL();
			}
			for (size_t i = 0; i < this->mechanisms.count(); i++) {
				pMechanismList[i] = this->mechanisms.items(i)->type;
			}
		}

		return CKR_OK;
	}
	CATCH_EXCEPTION;
}

CK_RV core::Slot::GetMechanismInfo
(
	CK_MECHANISM_TYPE     type,    /* type of mechanism */
	CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
)
{
	try {
		if (!this->hasMechanism(type)) {
			THROW_PKCS11_EXCEPTION (CKR_MECHANISM_INVALID, "Cannot get mechanism");
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
	CATCH_EXCEPTION;
}

bool core::Slot::hasMechanism(CK_MECHANISM_TYPE type) {
	for (size_t i = 0; i < this->mechanisms.count(); i++) {
		if (this->mechanisms.items(i)->type == type) {
			return true;
		}
	}
	return false;
}

bool core::Slot::hasSession(CK_SESSION_HANDLE hSession)
{
	for (size_t i = 0; i < this->sessions.count(); i++) {
		Scoped<Session> session = this->sessions.items(i);
		if (session->Handle == hSession) {
			return true;
		}
	}
}

CK_RV core::Slot::InitToken
(
	CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
	CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
	CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
)
{
	CHECK_ARGUMENT_NULL(pLabel);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV core::Slot::InitPIN
(
	CK_SESSION_HANDLE hSession,  /* the session's handle */
	CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
	CK_ULONG          ulPinLen   /* length in bytes of the PIN */
)
{
	CHECK_SESSION_HANDLE(hSession);

	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV core::Slot::OpenSession
(
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	try {
		Scoped<Session> session = this->CreateSession();
		CK_RV res = session->Open(flags, pApplication, Notify, phSession);
		if (res == CKR_OK) {
			session->SlotID = this->slotID;
			this->sessions.add(session);
		}
		return res;
	}
	CATCH_EXCEPTION;
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

	CK_RV res = session->Close();
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