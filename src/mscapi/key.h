#pragma once

#include "../stdafx.h"

#include "../core/objects/private_key.h"
#include "../core/objects/public_key.h"

#include "ncrypt.h"

namespace mscapi {

	class CryptoKey {
	public:
		CryptoKey(
			Scoped<ncrypt::Key> key
		);

		Scoped<ncrypt::Key> key;
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