#include "ec.h"

using namespace mscapi;

Scoped<CryptoKeyPair> EcKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate
)
{
    try {
        NTSTATUS status;
        Scoped<std::string> point = publicTemplate->GetBytes(CKA_EC_POINT, true, "");

        LPCWSTR pszAlgorithm;
        if (strcmp(core::EC_P256_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P256_ALGORITHM;
        }
        else if (strcmp(core::EC_P384_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P384_ALGORITHM;
        }
        else if (strcmp(core::EC_P384_BLOB, point->c_str()) == 0) {
            pszAlgorithm = NCRYPT_ECDSA_P521_ALGORITHM;
        }
        else {
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Wrong POINT for EC key");
        }

        // NCRYPT
        Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
        provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

        // TODO: Random name for key. If TOKEN flag is true
        auto key = provider->GenerateKeyPair(pszAlgorithm, NULL, 0, 0);

        // Key Usage
        ULONG keyUsage = 0;
        if (publicTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
            keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
        }
        if (publicTemplate->GetBool(CKA_DERIVE, false, false)) {
            keyUsage |= NCRYPT_ALLOW_KEY_AGREEMENT_FLAG;
        }
        key->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, keyUsage);
        // TODO: Extractable

        key->Finalize();

        Scoped<core::PrivateKey> privateKey(new EcPrivateKey(key));
        privateKey->propId = *privateTemplate->GetBytes(CKA_ID, false, "");

        Scoped<core::PublicKey> publicKey(new EcPublicKey(key));
        publicKey->propId = *publicTemplate->GetBytes(CKA_ID, false, "");

        return Scoped<CryptoKeyPair>(new CryptoKeyPair(privateKey, publicKey));
    }
    CATCH_EXCEPTION;
}

