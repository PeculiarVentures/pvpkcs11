#include "../stdafx.h"
#include "slot.h"
#include "session.h"

MscapiSlot::MscapiSlot() {
	SET_STRING(this->manufacturerID, "Windows CryptoAPI", 32);
	SET_STRING(this->description, "Windows CryptoAPI", 64);
	this->flags = CKF_TOKEN_INITIALIZED;
	this->hardwareVersion = { 0, 1 };
	this->firmwareVersion = { 0, 1 };

	// Token info

	// Add mechanisms
	//   SHA
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA_1, 0, 0, CKF_DIGEST)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA256, 0, 0, CKF_DIGEST)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA384, 0, 0, CKF_DIGEST)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA512, 0, 0, CKF_DIGEST)));
	//   RSA
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA1_RSA_PKCS, 0, 0, CKF_SIGN | CKF_VERIFY)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA256_RSA_PKCS, 0, 0, CKF_SIGN | CKF_VERIFY)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA384_RSA_PKCS, 0, 0, CKF_SIGN | CKF_VERIFY)));
	this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA512_RSA_PKCS, 0, 0, CKF_SIGN | CKF_VERIFY)));
}

Scoped<Session> MscapiSlot::CreateSession()
{
	return Scoped<MscapiSession>(new MscapiSession());
}
