#include "crypt.h"

using namespace crypt;

Scoped<Key> Key::Generate(
	Scoped<Provider>  prov,
	ALG_ID            uiAlgId,
	DWORD             dwFlags
)
{
	HCRYPTKEY hNewKey = NULL;
	if (!CryptGenKey(prov->Get(), uiAlgId, dwFlags, &hNewKey)) {
		THROW_MSCAPI_EXCEPTION();
	}

	Scoped<Key> result(new Key(hNewKey));
	return result;
}

Scoped<Key> Key::Import(
	Scoped<Provider>  prov,
	BYTE              *pbData,
	DWORD             dwDataLen,
	DWORD             dwFlags
)
{
	HCRYPTKEY hNewKey = NULL;

	if (!CryptImportKey(
		prov->Get(),
		pbData,
		dwDataLen,
		NULL,
		dwFlags,
		&hNewKey
	)) {
		THROW_MSCAPI_EXCEPTION();
	}

	Scoped<Key> result(new Key(hNewKey));
	return result;
}

Scoped<Key> Key::Import(
	Scoped<Provider>       prov,
	DWORD                  dwCertEncodingType,
	PCERT_PUBLIC_KEY_INFO  pInfo
)
{
	HCRYPTKEY hNewKey = NULL;

	if (!CryptImportPublicKeyInfo(
		prov->Get(),
		dwCertEncodingType,
		pInfo,
		&hNewKey
	)) {
		THROW_MSCAPI_EXCEPTION();
	}

	Scoped<Key> result(new Key(hNewKey));
	return result;
}

Key::Key()
{
	this->handle = NULL;
}

Key::Key(HCRYPTKEY handle)
{
	this->handle = handle;
}

Key::~Key()
{
	this->Destroy();
}

Scoped<Key> Key::Copy()
{
	HCRYPTKEY dupKey;
	if (!CryptDuplicateKey(this->handle, NULL, 0, &dupKey)) {
		THROW_MSCAPI_EXCEPTION();
	}
	return Scoped<Key>(new Key(dupKey));
}

void Key::Destroy()
{
	if (this->handle) {
		CryptDestroyKey(this->handle);
		this->handle = NULL;
	}
}

HCRYPTKEY Key::Get()
{
	return this->handle;
}

void Key::Assign(HCRYPTKEY value)
{
	this->Destroy();
	this->handle = value;
}

