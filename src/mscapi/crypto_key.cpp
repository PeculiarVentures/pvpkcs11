#include "crypto_key.h"
#include "helper.h"

#include "bcrypt/key.h"
#include "ncrypt/key.h"
#include "crypto.h"

using namespace mscapi;

Scoped<CryptoKey> CryptoKey::Create(PCERT_PUBLIC_KEY_INFO spki)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!spki) {
            THROW_PARAM_REQUIRED_EXCEPTION("spki");
        }

#pragma region Import SPKI to BKey
        ALG_ID dwAlgId = CertOIDToAlgId(spki->Algorithm.pszObjId);
        DWORD dwProvType = PROV_RSA_FULL;
        switch (dwAlgId) {
        case CALG_ECDH:
        case CALG_ECDSA:
            dwProvType = PROV_EC_ECDSA_FULL;
        }

        Scoped<bcrypt::Key> bKey(new bcrypt::Key);
        bKey->ImportPublicKeyInfo(X509_ASN_ENCODING, spki);
#pragma endregion

#pragma region Translate BKey to NKey
        NTSTATUS status = 0;

        Scoped<std::wstring> algName = bKey->GetAlgorithmName();

        LPWSTR blobType = BCRYPT_RSAPUBLIC_BLOB;

        if (algName->compare(BCRYPT_RSA_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_RSA_SIGN_ALGORITHM) == 0) {
            blobType = BCRYPT_RSAPUBLIC_BLOB;
        }
        else if (algName->compare(BCRYPT_ECDH_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDSA_P256_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDSA_P384_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDSA_P521_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDH_P256_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDH_P384_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDH_P521_ALGORITHM) == 0 ||
            algName->compare(BCRYPT_ECDSA_ALGORITHM) == 0) {
            blobType = BCRYPT_ECCPUBLIC_BLOB;
        }
        else {
            std::string algNameA(algName->begin(), algName->end()); // convert to string
            THROW_EXCEPTION("Unsupported algorithm '%s'", algNameA.c_str());
        }

        Scoped<Buffer> blobBuffer = bKey->Export(blobType);

        Scoped<ncrypt::Key> nKey(new ncrypt::Key);
        nKey->Import(blobType, blobBuffer);
#pragma endregion

        Scoped<CryptoKey> cryptoKey(new CryptoKey);
        cryptoKey->key = nKey;

        return cryptoKey;

    }
    CATCH_EXCEPTION
}

CryptoKey::CryptoKey() :
    key(NULL),
    info(NULL)
{
}

CryptoKey::CryptoKey(Scoped<Handle<HCRYPTPROV_OR_NCRYPT_KEY_HANDLE>> key):
    CryptoKey() 
{
    this->key = key;
}

CryptoKey::CryptoKey(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle, DWORD dwKeySpec) :
    CryptoKey()
{
    if (NCryptIsKeyHandle(handle)) {
        // CNG
        key = Scoped<ncrypt::Key>(new ncrypt::Key(handle));
    }
    else {
        key = Scoped<crypt::Key>(new crypt::Key(handle));

#pragma region try to convert CAPI to CNG
        NTSTATUS status = 0;
        NCRYPT_KEY_HANDLE hNKey = NULL;
        status = NCryptTranslateHandle(NULL, &hNKey, handle, NULL, dwKeySpec, 0);
        if (!status) {
            key = Scoped<ncrypt::Key>(new ncrypt::Key(hNKey));
        }
#pragma endregion
    }
}

CryptoKey::CryptoKey(Scoped<crypt::ProviderInfo> info) :
    CryptoKey()
{
    this->info = info;
}

BOOL CryptoKey::IsCNG()
{
    return NCryptIsKeyHandle(Get());
}

HCRYPTPROV_OR_NCRYPT_KEY_HANDLE CryptoKey::Get()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = 0;

        if (!key.get()) {
            HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey = NULL;
            PCRYPT_KEY_PROV_INFO provInfo = info->Get();

            if (provInfo->dwProvType) {
                // CAPI
                Scoped<crypt::Key> ckey(new crypt::Key);
                ckey->Open(provInfo);
                hKey = ckey->Get();

#pragma region try to convert CAPI to CNG
                NCRYPT_KEY_HANDLE hNKey = NULL;
                status = NCryptTranslateHandle(NULL, &hNKey, hKey, NULL, provInfo->dwKeySpec, 0);
                if (!status) {
                    key = Scoped<ncrypt::Key>(new ncrypt::Key(hNKey));
                }
                else {
                    key = ckey;
                }
#pragma endregion
            }
            else {
                // CNG
                Scoped<ncrypt::Key> nkey(new ncrypt::Key);
                nkey->Open(provInfo);

                key = nkey;
            }
        }

        return key->Get();
    }
    CATCH_EXCEPTION
}

DWORD CryptoKey::GetKeySpec()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (info.get()) {
            // ProvInfo
            return info->Get()->dwKeySpec;
        }
        else if (IsCNG()) {
            return AT_KEYEXCHANGE;
        }
        else {
            // CAPI
            return GetCKey()->GetNumber(PP_KEYSPEC);
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> CryptoKey::GetID()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> spki(new Buffer(0));
        DWORD dwSpkiLen = 0;

        auto pubKeyInfo = ExportPublicKeyInfo(Get());

        return DIGEST_SHA1(pubKeyInfo->PublicKey.pbData, pubKeyInfo->PublicKey.cbData);
    }
    CATCH_EXCEPTION
}

crypt::Key * CryptoKey::GetCKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Get();

        crypt::Key* res = dynamic_cast<crypt::Key*>(key.get());
        if (!res) {
            THROW_EXCEPTION("Key is not CAPI");
        }

        return res;
    }
    CATCH_EXCEPTION
}

ncrypt::Key * CryptoKey::GetNKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Get();

        ncrypt::Key* res = dynamic_cast<ncrypt::Key*>(key.get());
        if (!res) {
            THROW_EXCEPTION("Key is not CNG");
        }

        return res;
    }
    CATCH_EXCEPTION
}
