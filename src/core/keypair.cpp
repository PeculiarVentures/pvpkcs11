#include "keypair.h"

using namespace core;

core::KeyPair::KeyPair(Scoped<PrivateKey> privateKey, Scoped<PublicKey> publicKey) :
    privateKey(privateKey),
    publicKey(publicKey)
{
}
