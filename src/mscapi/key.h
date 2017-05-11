#pragma once

#include "../stdafx.h"

#include "../core/objects/private_key.h"
#include "../core/objects/public_key.h"

#include "ncrypt.h"
#include "bcrypt.h"

namespace mscapi {

	class CryptoKey {
	public:
		CryptoKey(
			Scoped<ncrypt::Key> key
		);
        CryptoKey(
            Scoped<bcrypt::Key> key
        );

		Scoped<ncrypt::Key> nkey;
        Scoped<bcrypt::Key> bkey;
	};

	class CryptoKeyPair {
	public:
		CryptoKeyPair(
			Scoped<core::PrivateKey> privateKey, 
			Scoped<core::PublicKey> publicKey
		);

		Scoped<core::PrivateKey> privateKey;
		Scoped<core::PublicKey>  publicKey;
	};

}