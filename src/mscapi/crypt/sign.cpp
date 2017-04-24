#include "crypt.h"

using namespace crypt;

Scoped<Sign> Sign::Create(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	try {
		Scoped<Sign> sign(new Sign(algId, key));
		return sign;
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Sign::Once(
	ALG_ID        algId,
	Scoped<Key>   key,
	BYTE*         pbData,
	DWORD         dwDataLen
)
{
	try {
		Scoped<Sign> sign(new Sign(algId, key));
		sign->Update(pbData, dwDataLen);
		return sign->Final();
	}
	CATCH_EXCEPTION;
}

Sign::Sign(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	try {
		hash = Hash::Create(key->GetProvider(), algId, NULL, 0);
		this->key = key;
	}
	CATCH_EXCEPTION;
}

void Sign::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	try {
		hash->Update(pPart, ulPartLen);
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Sign::Final()
{
	try {
		Scoped<std::string> result(new std::string());
		DWORD dwDataLen;
		// Calculate signature
		if (!CryptSignHash(hash->Get(), AT_SIGNATURE, NULL, 0, NULL, &dwDataLen)) {
			THROW_MSCAPI_ERROR();
		}
		result->resize(dwDataLen);
		if (!CryptSignHash(hash->Get(), AT_SIGNATURE, NULL, 0, (BYTE*)result->c_str(), &dwDataLen)) {
			THROW_MSCAPI_ERROR();
		}

		// reverse signature
		std::reverse(result->begin(), result->end());

		return result;
	}
	CATCH_EXCEPTION;

}
