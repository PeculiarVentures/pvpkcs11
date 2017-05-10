#include "rsa.h"
#include "helper.h"
#include "ncrypt.h"

using namespace mscapi;

Scoped<CryptoKeyPair> RsaKey::Generate(
	CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
	Scoped<core::Template> publicTemplate,
	Scoped<core::Template> privateTemplate
)
{
	try {
		NTSTATUS status;
		ULONG modulusLength = publicTemplate->GetNumber(CKA_MODULUS_BITS, true, 0);

		// NCRYPT
		Scoped<ncrypt::Provider> provider(new ncrypt::Provider());
		provider->Open(MS_KEY_STORAGE_PROVIDER, 0);

		// TODO: Random name for key. If TOKEN flag is true
		auto key = provider->GenerateKeyPair(NCRYPT_RSA_ALGORITHM, NULL, 0, 0);

		// Public exponent
		auto publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
		char PUBLIC_EXPONENT_65537[3] = { 1,0,1 };
		if (!(publicExponent->length() == 3 && !strncmp(publicExponent->c_str(), PUBLIC_EXPONENT_65537, 3))) {
			THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
		}
		// Modulus length
		key->SetNumber(NCRYPT_LENGTH_PROPERTY, publicTemplate->GetNumber(CKA_MODULUS_BITS, true));
		// Key Usage
		ULONG keyUsage = 0;
		if (publicTemplate->GetBool(CKA_SIGN, false, false) || publicTemplate->GetBool(CKA_VERIFY, false, false)) {
			keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
		}
		if (publicTemplate->GetBool(CKA_ENCRYPT, false, false) || publicTemplate->GetBool(CKA_DECRYPT, false, false) ||
			publicTemplate->GetBool(CKA_WRAP, false, false) || publicTemplate->GetBool(CKA_UNWRAP, false, false)) {
			keyUsage |= NCRYPT_ALLOW_SIGNING_FLAG;
		}
		key->SetNumber(NCRYPT_KEY_USAGE_PROPERTY, keyUsage);
		// TODO: Extractable

		key->Finalize();

		Scoped<core::PrivateKey> privateKey(new RsaPrivateKey(key));
		privateKey->propId = *privateTemplate->GetBytes(CKA_ID, false, "");

		Scoped<core::PublicKey> publicKey(new RsaPublicKey(key));
		publicKey->propId = *publicTemplate->GetBytes(CKA_ID, false, "");

		return Scoped<CryptoKeyPair> (new CryptoKeyPair(privateKey, publicKey));
	}
	CATCH_EXCEPTION;
}