#include "key.h"

#include "crypt/crypt.h"

using namespace mscapi;

mscapi::CryptoKey::CryptoKey()
{
}

mscapi::CryptoKey::~CryptoKey()
{
    if (provInfo) {
        provInfo = NULL;
    }
}

void mscapi::CryptoKey::Assign(
    Scoped<crypt::ProviderInfo> info
)
{
    provInfo = info;
}

void mscapi::CryptoKey::Assign(
    Scoped<ncrypt::Key> key
)
{
    nkey = key;
    OnKeyAssigned();
}

void mscapi::CryptoKey::Assign(
    Scoped<bcrypt::Key> key
)
{
    bkey = key;
}

void mscapi::CryptoKey::OnKeyAssigned() {
}

mscapi::CryptoKeyPair::CryptoKeyPair(
    Scoped<core::PrivateKey> privateKey,
    Scoped<core::PublicKey> publicKey
) :
    privateKey(privateKey),
    publicKey(publicKey)
{
}

Scoped<ncrypt::Key> mscapi::CryptoKey::GetNKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!nkey.get()) {
            if (!provInfo) {
                THROW_EXCEPTION("Key doesn't have CRYPT_KEY_PROV_INFO to acquire key");
            }

            if (provInfo->Get()->dwProvType) {
                // CAPI
                crypt::Provider provider;
                ncrypt::Provider nprov;
                Scoped<crypt::Key> key;

                provider.AcquireContextW(
                    provInfo->Get()->pwszContainerName,
                    provInfo->Get()->pwszProvName,
                    provInfo->Get()->dwProvType,
                    0
                );

                /*LPCWSTR msStorage = MS_KEY_STORAGE_PROVIDER;
                if (provider.HasParam(PP_SMARTCARD_GUID) || provider.HasParam(PP_SMARTCARD_READER)) {
                    msStorage = MS_SMART_CARD_KEY_STORAGE_PROVIDER;
                }*/

                try {
                    nprov.Open(MS_KEY_STORAGE_PROVIDER, 0);
                    key = provider.GetUserKey(provInfo->Get()->dwKeySpec);
                    return nprov.TranslateHandle(provider.Get(), key->Get(), 0, 0);
                }
                catch (Scoped<core::Exception> e) {
                    LOGGER_ERROR(e->what());
                    try {
                        nprov.Open(MS_SMART_CARD_KEY_STORAGE_PROVIDER, 0);
                        key = provider.GetUserKey(provInfo->Get()->dwKeySpec);
                        return nprov.TranslateHandle(provider.Get(), key->Get(), 0, 0);
                    }
                    catch (Scoped<core::Exception> e) {
                        LOGGER_ERROR(e->what());
                        THROW_EXCEPTION("Cannot translate CAPI key to CNG");
                    }
                }
            }
            else {
                // CNG
                ncrypt::Provider prov;
                prov.Open(provInfo->Get()->pwszProvName, 0);
                return prov.OpenKey(provInfo->Get()->pwszContainerName, provInfo->Get()->dwKeySpec, provInfo->Get()->dwFlags);
            }

        }

        return nkey;
    }
    CATCH_EXCEPTION
}

Scoped<bcrypt::Key> mscapi::CryptoKey::GetBKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!bkey.get()) {
            THROW_EXCEPTION("Cannot get bcrypt key. It's empty");
        }
    }
    CATCH_EXCEPTION
}