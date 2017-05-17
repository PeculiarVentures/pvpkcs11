#include "key.h"

using namespace mscapi;

void CryptoKey::Assign(
    Scoped<ncrypt::Key> key
)
{
    nkey = key;
}

void CryptoKey::Assign(
    Scoped<bcrypt::Key> key
)
{
    bkey = key;
}

CryptoKeyPair::CryptoKeyPair(
    Scoped<core::PrivateKey> privateKey,
    Scoped<core::PublicKey> publicKey
) :
    privateKey(privateKey),
    publicKey(publicKey)
{
}