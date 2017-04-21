#include "crypt.h"

using namespace crypt;

Scoped<Sign> Sign::Create(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	Scoped<Sign> sign(new Sign(algId, key));
	return sign;
}

Scoped<std::string> Sign::Once(
	ALG_ID        algId,
	Scoped<Key>   key,
	BYTE*         pbData,
	DWORD         dwDataLen
)
{
	Scoped<Sign> sign(new Sign(algId, key));
	sign->Update(pbData, dwDataLen);
	return sign->Final();
}

Sign::Sign(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	hash = Hash::Create(key->getProvider(), algId, NULL, 0);
	this->key = key;
}

void Sign::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	hash->Update(pPart, ulPartLen);
}

Scoped<std::string> Sign::Final()
{
	Scoped<std::string> result(new std::string());
	DWORD dwDataLen;
	// Calculate signature
	if (!CryptSignHash(hash->Get(), AT_SIGNATURE, NULL, 0, NULL, &dwDataLen)) {
		THROW_MS_ERROR();
	}
	result->resize(dwDataLen);
	if (!CryptSignHash(hash->Get(), AT_SIGNATURE, NULL, 0, (BYTE*)result->c_str(), &dwDataLen)) {
		THROW_MS_ERROR();
	}

	// reverse signature
	std::reverse(result->begin(), result->end());

	return result;
}
