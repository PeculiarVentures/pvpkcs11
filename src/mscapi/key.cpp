#include "key.h"

using namespace mscapi;

CryptoKey::CryptoKey(
    Scoped<ncrypt::Key> key
) :
    nkey(key)
{
}

CryptoKey::CryptoKey(
    Scoped<bcrypt::Key> key
) :
    bkey(key)
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