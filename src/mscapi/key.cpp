#include "key.h"

using namespace mscapi;

mscapi::CryptoKeyPair::CryptoKeyPair(
    Scoped<core::PrivateKey> privateKey,
    Scoped<core::PublicKey> publicKey
) :
    privateKey(privateKey),
    publicKey(publicKey)
{
}


Scoped<CryptoKey> mscapi::ObjectKey::GetKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!key.get()) {
            THROW_EXCEPTION("CryptoKey is empty");
        }

        return key;
    }
    CATCH_EXCEPTION
}

void mscapi::ObjectKey::SetKey(Scoped<CryptoKey> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (key.get()) {
            THROW_EXCEPTION("Cannot reset CryptoKey");
        }

        key = value;
    }
    CATCH_EXCEPTION
}

void mscapi::ObjectKey::SetKey(Scoped<Handle<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetKey(Scoped<CryptoKey>(new CryptoKey(value)));
    }
    CATCH_EXCEPTION
}