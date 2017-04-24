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
		THROW_MSCAPI_ERROR();
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
		THROW_MSCAPI_ERROR();
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
		THROW_MSCAPI_ERROR();
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
		THROW_MSCAPI_ERROR();
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
			THROW_MSCAPI_ERROR();
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
		THROW_MSCAPI_ERROR();
	}
}

void Key::SetParam(DWORD dwPropId, BYTE* pbData, DWORD dwFlags)
{
	if (!CryptSetKeyParam(handle, dwPropId, pbData, dwFlags)) {
		THROW_MSCAPI_ERROR();
	}
}

DWORD Key::GetNumber(DWORD dwPropId)
{
	try {
		DWORD dwData;
		DWORD dwDataLen = sizeof(DWORD);
		this->GetParam(dwPropId, (BYTE*)&dwData, &dwDataLen);

		return dwData;
	}
	CATCH_EXCEPTION;
}

DWORD Key::GetKeyLen()
{
	try {
		return this->GetNumber(KP_KEYLEN) >> 3;
	}
	CATCH_EXCEPTION;
}

DWORD Key::GetBlockLen()
{
	try {
		return this->GetNumber(KP_BLOCKLEN) >> 3;
	}
	CATCH_EXCEPTION;
}

ALG_ID Key::GetAlgId()
{
	try {
		return this->GetNumber(KP_ALGID);
	}
	CATCH_EXCEPTION;
}

void Key::SetIV(BYTE* pbData, DWORD dwDataLen)
{
	try {
		this->SetParam(KP_IV, pbData);
	}
	CATCH_EXCEPTION;
}

DWORD Key::GetMode()
{
	try {
		return this->GetNumber(KP_MODE);
	}
	CATCH_EXCEPTION;
}

void Key::SetNumber(DWORD dwPropId, DWORD dwData)
{
	try {
		this->SetParam(dwPropId, (BYTE*)&dwData, sizeof(DWORD));
	}
	CATCH_EXCEPTION;
}

DWORD Key::GetPadding()
{
	try {
		return this->GetNumber(KP_PADDING);
	}
	CATCH_EXCEPTION;
}

void Key::SetPadding(DWORD dwPadding)
{
	try {
		this->SetNumber(KP_PADDING, dwPadding);
	}
	CATCH_EXCEPTION;
}
