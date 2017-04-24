#include "../stdafx.h"
#include "slot.h"
#include "session.h"

MscapiSlot::MscapiSlot() {
	try {
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
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, 1024, 4096, CKF_GENERATE)));
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA1_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA256_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA384_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_SHA512_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
		//   AES
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_AES_KEY_GEN, 128, 256, CKF_GENERATE)));
		this->mechanisms.add(Scoped<Mechanism>(new Mechanism(CKM_AES_CBC_PAD, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
	}
	CATCH_EXCEPTION;
}

Scoped<Session> MscapiSlot::CreateSession()
{
	try {
		return Scoped<MscapiSession>(new MscapiSession());
	}
	CATCH_EXCEPTION;
}
