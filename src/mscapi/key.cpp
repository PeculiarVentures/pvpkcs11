#include "key.h"

Scoped<MscapiKey> MscapiKey::Copy()
{
	HCRYPTKEY hNewKey = NULL;
	if (!CryptDuplicateKey(this->handle, NULL, 0, &hNewKey)) {
		throw std::exception("CryptDuplicateKey");
	}
	Scoped<MscapiKey> key(new MscapiKey());
	key->handle = hNewKey;

	return key;
}

void MscapiKey::Destroy()
{
	if (this->handle) {
		CryptDestroyKey(this->handle);
		this->handle = NULL;
	}
}

Scoped<MscapiKey> MscapiKey::Generate(HCRYPTPROV hProv, ALG_ID uiAlgId, DWORD dwFlags)
{
	HCRYPTKEY hNewKey = NULL;
	if (!CryptGenKey(hProv, uiAlgId, dwFlags, &hNewKey)) {
		throw std::exception("CryptGenKey");
	}

	Scoped<MscapiKey > key(new MscapiKey());
	key->handle = hNewKey;

	return key;
}

Scoped<MscapiKey> MscapiKey::Import(
	_In_                    HCRYPTPROV  hProv,
	_In_reads_bytes_(dwDataLen)  CONST BYTE  *pbData,
	_In_                    DWORD       dwDataLen,
	_In_                    DWORD       dwFlags
)
{
	HCRYPTKEY hNewKey = NULL;

	if (!CryptImportKey(
		hProv,
		pbData,
		dwDataLen,
		NULL,
		dwFlags,
		&hNewKey
	)) {
		throw std::exception("CryptImportKey");
	}

	Scoped<MscapiKey> key(new MscapiKey());
	key->handle = hNewKey;

	return key;
}