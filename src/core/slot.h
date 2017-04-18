#pragma once

#include "collection.h"
#include "objects/mechanism.h"
#include "session.h"

class Slot
{
public:
	Collection<Scoped<Mechanism>> mechanisms;
	Collection<Scoped<Session>> sessions;

	Slot();
	~Slot();

	CK_UTF8CHAR   description[64];
	CK_UTF8CHAR	  manufacturerID[32];
	CK_FLAGS      flags;
	CK_VERSION    hardwareVersion;  /* version of hardware */
	CK_VERSION    firmwareVersion;  /* version of firmware */

	CK_SLOT_ID    slotID;

	CK_RV GetSlotInfo(
		CK_SLOT_INFO_PTR pInfo    /* receives the slot information */
	);

	CK_RV GetTokenInfo
	(
		CK_TOKEN_INFO_PTR pInfo    /* receives the token information */
	);

	CK_RV GetMechanismList
	(
		CK_MECHANISM_TYPE_PTR pMechanismList,  /* gets mech. array */
		CK_ULONG_PTR          pulCount         /* gets # of mechs. */
	);

	CK_RV GetMechanismInfo
	(
		CK_MECHANISM_TYPE     type,    /* type of mechanism */
		CK_MECHANISM_INFO_PTR pInfo    /* receives mechanism info */
	);

	CK_RV InitToken
	(
		CK_UTF8CHAR_PTR pPin,      /* the SO's initial PIN */
		CK_ULONG        ulPinLen,  /* length in bytes of the PIN */
		CK_UTF8CHAR_PTR pLabel     /* 32-byte token label (blank padded) */
	);

	CK_RV InitPIN
	(
		CK_SESSION_HANDLE hSession,  /* the session's handle */
		CK_UTF8CHAR_PTR   pPin,      /* the normal user's PIN */
		CK_ULONG          ulPinLen   /* length in bytes of the PIN */
	);

	CK_RV OpenSession
	(
		CK_FLAGS              flags,         /* from CK_SESSION_INFO */
		CK_VOID_PTR           pApplication,  /* passed to callback */
		CK_NOTIFY             Notify,        /* callback function */
		CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
	);

	CK_RV CloseSession
	(
		CK_SESSION_HANDLE hSession  /* the session's handle */
	);

	CK_RV CloseAllSessions();

	bool hasSession(CK_SESSION_HANDLE hSession);
	Scoped<Session> getSession(CK_SESSION_HANDLE hSession);
	CK_TOKEN_INFO tokenInfo;

protected:
	virtual Scoped<Session> CreateSession() = 0;
	bool hasMechanism(CK_MECHANISM_TYPE type);

};

