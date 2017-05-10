#include "key.h"

using namespace mscapi;
CryptoKey::CryptoKey(
	Scoped<ncrypt::Key> key
) :
	key(key)
{
}

CryptoKeyPair::CryptoKeyPair(
	Scoped<core::PrivateKey> privateKey, 
	Scoped<core::PublicKey> publicKey
) :
	privateKey(privateKey),
	publicKey(publicKey)
{
}