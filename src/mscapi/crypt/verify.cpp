#include "crypt.h"

using namespace crypt;

#include "crypt.h"

using namespace crypt;

Scoped<Verify> Verify::Create(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	Scoped<Verify> verify(new Verify(algId, key));
	return verify;
}

bool Verify::Once(
	ALG_ID        algId,
	Scoped<Key>   key,
	BYTE*         pbData,
	DWORD         dwDataLen,
	BYTE*         pbSignature,
	DWORD         dwSignatureLen
)
{
	Scoped<Verify> verify(new Verify(algId, key));
	verify->Update(pbData, dwDataLen);
	return verify->Final(pbSignature, dwSignatureLen);
}

Verify::Verify(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	hash = Hash::Create(key->getProvider(), algId, NULL, 0);
	this->key = key;
}

void Verify::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	hash->Update(pPart, ulPartLen);
}

bool Verify::Final(
	BYTE*  pbSignature,
	DWORD  dwSignatureLen
)
{
	// reverse signature
	BYTE*  pbSignatureReversed = (BYTE*)malloc(dwSignatureLen);
	memcpy(pbSignatureReversed, pbSignature, dwSignatureLen);
	std::reverse(&pbSignatureReversed[0], &pbSignatureReversed[dwSignatureLen]);

	// Calculate signature
	if (!CryptVerifySignature(hash->Get(), pbSignatureReversed, dwSignatureLen, this->key->Get(), NULL, 0)) {
		free(pbSignatureReversed);
		DWORD dwLastError = GetLastError();
		if (dwLastError == NTE_BAD_SIGNATURE) {
			return false;
		}
		throw Exception(dwLastError, __FUNCTION__);
	}
	free(pbSignatureReversed);

	return true;
}
