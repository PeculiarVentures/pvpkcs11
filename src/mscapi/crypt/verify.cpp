#include "crypt.h"

using namespace crypt;

#include "crypt.h"

using namespace crypt;

Scoped<Verify> Verify::Create(
	ALG_ID            algId,
	Scoped<Key>       key
)
{
	try {
		Scoped<Verify> verify(new Verify(algId, key));
		return verify;
	}
	CATCH_EXCEPTION;
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
	try {
		Scoped<Verify> verify(new Verify(algId, key));
		verify->Update(pbData, dwDataLen);
		return verify->Final(pbSignature, dwSignatureLen);
	}
	CATCH_EXCEPTION;
}

Verify::Verify(
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

void Verify::Update(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	try {
		hash->Update(pPart, ulPartLen);
	}
	CATCH_EXCEPTION;
}

bool Verify::Final(
	BYTE*  pbSignature,
	DWORD  dwSignatureLen
)
{
	try {
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
			THROW_MSCAPI_CODE_ERROR(dwLastError);
		}
		free(pbSignatureReversed);

		return true;
	}
	CATCH_EXCEPTION
}
