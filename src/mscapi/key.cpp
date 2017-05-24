#include "key.h"

using namespace mscapi;

void CryptoKey::Assign(
    Scoped<ncrypt::Key> key
)
{
    nkey = key;
    OnKeyAssigned();
}

void CryptoKey::Assign(
    Scoped<bcrypt::Key> key
)
{
    bkey = key;
}

void CryptoKey::OnKeyAssigned() {
}

CryptoKeyPair::CryptoKeyPair(
    Scoped<core::PrivateKey> privateKey,
    Scoped<core::PublicKey> publicKey
) :
    privateKey(privateKey),
    publicKey(publicKey)
{
}
