#include "crypt.h"

using namespace crypt;

Scoped<Hash> Hash::Create(
	Scoped<Provider>  prov,
	ALG_ID            algId,
	Scoped<Key>       key,
	DWORD             dwFlag
)
{
	return Scoped<Hash>(new Hash(prov, algId, key, dwFlag));
}

Hash::Hash(
	Scoped<Provider>  prov,
	ALG_ID            algId,
	Scoped<Key>       key,
	DWORD             dwFlag
):
	prov(prov),
	key(key)
{
	if (!CryptCreateHash(prov ? prov->Get() : NULL, algId, key ? key->Get() : NULL, dwFlag, &this->handle)) {
		THROW_MS_ERROR();
	}
}

void Hash::Update(
	BYTE* pbData,
	DWORD dwDataLen
)
{
	if (!CryptHashData(this->handle, pbData, dwDataLen, 0)) {
		THROW_MS_ERROR();
	}
}

void Hash::GetParam(DWORD dwPropId, BYTE* pvData, DWORD* pdwDataLen)
{
	if (!CryptGetHashParam(this->handle, dwPropId, pvData, pdwDataLen, 0)) {
		THROW_MS_ERROR();
	}
}

DWORD Hash::GetNumber(DWORD dwPropId)
{
	DWORD dwData;
	DWORD dwDataLen = sizeof(DWORD);
	this->GetParam(dwPropId, (BYTE*)&dwData, &dwDataLen);
	return dwData;
}

DWORD Hash::GetSize()
{
	return this->GetNumber(HP_HASHSIZE);
}

DWORD Hash::GetAlgId()
{
	return this->GetNumber(HP_ALGID);
}

Scoped<std::string> Hash::GetValue()
{
	DWORD dwDataLen = this->GetSize();
	Scoped<std::string> result(new std::string());
	result->resize(dwDataLen);
	this->GetParam(HP_HASHVAL, (BYTE*)result->c_str(), &dwDataLen);
	return result;
}

Scoped<std::string> Hash::Once(
	DWORD    provType,
	ALG_ID   algId,
	BYTE*    pbData,
	DWORD    dwDataLen
)
{
	Scoped<Provider> prov = Provider::Create(NULL, NULL, provType, 0);
	Scoped<Hash> hash = Hash::Create(prov, algId, NULL, 0);
	hash->Update(pbData, dwDataLen);
	return hash->GetValue();
}

HCRYPTHASH Hash::Get()
{
	return this->handle;
}