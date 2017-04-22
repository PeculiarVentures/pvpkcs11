#include "crypt.h"
#include "../helper.h"

using namespace crypt;

Scoped<Key> Key::Generate(
	Scoped<Provider>  prov,
	ALG_ID            uiAlgId,
	DWORD             dwFlags
)
{
	HCRYPTKEY hNewKey = NULL;
	if (!CryptGenKey(prov->Get(), uiAlgId, dwFlags, &hNewKey)) {
		PRINT_WIN_ERROR();
		THROW_MS_ERROR();
	}

	Scoped<Key> result(new Key(hNewKey));
	result->prov = prov;
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
		THROW_MS_ERROR();
	}

	Scoped<Key> result(new Key(hNewKey));
	result->prov = prov;
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
		THROW_MS_ERROR();
	}

	Scoped<Key> result(new Key(hNewKey));
	result->prov = prov;
	return result;
}

Key::Key()
{
	this->handle = NULL;
}

Key::Key(Scoped<Provider> prov)
	: Key()
{
	this->prov = prov;
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
		THROW_MS_ERROR();
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
	if (this->handle == NULL) {
		if (!CryptGetUserKey(this->prov->Get(), AT_SIGNATURE, &this->handle)) {
			PRINT_WIN_ERROR();
			THROW_MS_ERROR();
		}
	}
	return this->handle;
}

void Key::Set(HCRYPTKEY value)
{
	this->Destroy();
	this->handle = value;
}

Scoped<Provider> Key::GetProvider()
{
	return this->prov;
}

void Key::GetParam(DWORD dwPropId, BYTE* pbData, DWORD* pdwDataLen, DWORD dwFlags)
{
	if (!CryptGetKeyParam(handle, dwPropId, pbData, pdwDataLen, dwFlags)) {
		THROW_MS_ERROR();
	}
}

void Key::SetParam(DWORD dwPropId, BYTE* pbData, DWORD dwFlags)
{
	if (!CryptSetKeyParam(handle, dwPropId, pbData, dwFlags)) {
		THROW_MS_ERROR();
	}
}

DWORD Key::GetNumber(DWORD dwPropId)
{
	DWORD dwData;
	DWORD dwDataLen = sizeof(DWORD);
	this->GetParam(dwPropId, (BYTE*)&dwData, &dwDataLen);

	return dwData;
}

DWORD Key::GetBlockLen()
{
	return this->GetNumber(KP_BLOCKLEN) >> 3;
}

ALG_ID Key::GetAlgId()
{
	return this->GetNumber(KP_ALGID);
}

void Key::SetIV(BYTE* pbData, DWORD dwDataLen)
{
	this->SetParam(KP_IV, pbData);
}

DWORD Key::GetMode()
{
	return this->GetNumber(KP_MODE);
}

void Key::SetNumber(DWORD dwPropId, DWORD dwData)
{
	this->SetParam(dwPropId, (BYTE*)&dwData, sizeof(DWORD));
}

DWORD Key::GetPadding()
{
	return this->GetNumber(KP_PADDING);
}

void Key::SetPadding(DWORD dwPadding)
{
	this->SetNumber(KP_PADDING, dwPadding);
}
