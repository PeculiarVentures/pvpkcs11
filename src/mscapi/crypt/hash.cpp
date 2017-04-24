#include "crypt.h"

using namespace crypt;

Scoped<Hash> Hash::Create(
	Scoped<Provider>  prov,
	ALG_ID            algId,
	Scoped<Key>       key,
	DWORD             dwFlag
)
{
	try {
		return Scoped<Hash>(new Hash(prov, algId, key, dwFlag));
	}
	CATCH_EXCEPTION;
}

Hash::Hash(
	Scoped<Provider>  prov,
	ALG_ID            algId,
	Scoped<Key>       key,
	DWORD             dwFlag
) :
	prov(prov),
	key(key)
{
	try {
		if (!CryptCreateHash(prov ? prov->Get() : NULL, algId, key ? key->Get() : NULL, dwFlag, &this->handle)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

void Hash::Update(
	BYTE* pbData,
	DWORD dwDataLen
)
{
	try {
		if (!CryptHashData(this->handle, pbData, dwDataLen, 0)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

void Hash::GetParam(DWORD dwPropId, BYTE* pvData, DWORD* pdwDataLen)
{
	try {
		if (!CryptGetHashParam(this->handle, dwPropId, pvData, pdwDataLen, 0)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

DWORD Hash::GetNumber(DWORD dwPropId)
{
	try {
		DWORD dwData;
		DWORD dwDataLen = sizeof(DWORD);
		this->GetParam(dwPropId, (BYTE*)&dwData, &dwDataLen);
		return dwData;
	}
	CATCH_EXCEPTION;
}

DWORD Hash::GetSize()
{
	try {
		return this->GetNumber(HP_HASHSIZE);
	}
	CATCH_EXCEPTION;
}

DWORD Hash::GetAlgId()
{
	try {
		return this->GetNumber(HP_ALGID);
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Hash::GetValue()
{
	try {
		DWORD dwDataLen = this->GetSize();
		Scoped<std::string> result(new std::string());
		result->resize(dwDataLen);
		this->GetParam(HP_HASHVAL, (BYTE*)result->c_str(), &dwDataLen);
		return result;
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Hash::Once(
	DWORD    provType,
	ALG_ID   algId,
	BYTE*    pbData,
	DWORD    dwDataLen
)
{
	try {
		Scoped<Provider> prov = Provider::Create(NULL, NULL, provType, 0);
		Scoped<Hash> hash = Hash::Create(prov, algId, NULL, 0);
		hash->Update(pbData, dwDataLen);
		return hash->GetValue();
	}
	CATCH_EXCEPTION;
}

HCRYPTHASH Hash::Get()
{
	try {
		return this->handle;
	}
	CATCH_EXCEPTION;
}