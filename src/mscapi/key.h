#pragma once

#include "../stdafx.h"

#include "../core/objects/private_key.h"
#include "../core/objects/public_key.h"

#include "crypt/crypt.h"
#include "ncrypt.h"
#include "bcrypt.h"

namespace mscapi {

	class CryptoKey {
	public:
        CryptoKey();
        ~CryptoKey();

		void Assign(
			Scoped<ncrypt::Key> key
		);
        void Assign(
            Scoped<bcrypt::Key> key
        );
        void Assign(
            Scoped<crypt::ProviderInfo> provInfo
        );

        virtual void OnKeyAssigned();

        Scoped<ncrypt::Key> GetNKey();
        Scoped<bcrypt::Key> GetBKey();

    protected:
        Scoped<crypt::ProviderInfo> provInfo;

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