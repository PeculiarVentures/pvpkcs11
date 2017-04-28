#include "cng.h"

using namespace cng;

CryptoKey::CryptoKey(BCRYPT_KEY_HANDLE handle)
{
	this->handle = handle;
}

void CryptoKey::Destroy()
{
	if (handle) {
		BCryptDestroyKey(handle);
		handle = NULL;
	}
}

Scoped<CryptoKey> CryptoKey::Duplicate()
{
	BCRYPT_KEY_HANDLE hDupKey;
	NTSTATUS status = BCryptDuplicateKey(handle, &hDupKey, NULL, 0, 0);
	
	if (status) {
		THROW_NT_EXCEPTION(status);
	}

	return Scoped<CryptoKey>(new CryptoKey(hDupKey));
}