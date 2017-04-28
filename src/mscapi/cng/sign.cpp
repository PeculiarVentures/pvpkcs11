#include "cng.h"

using namespace cng;

Scoped<CryptoSign> CryptoSign::Create(
	LPCWSTR pszAlgId,
	Scoped<CryptoKey> key
)
{
	try {
		Scoped<CryptoSign> result(new CryptoSign());
		result->pszAlgId = (LPCWSTR)malloc(lstrlenW(pszAlgId));
		memcpy((void*)result->pszAlgId, pszAlgId, lstrlenW(pszAlgId));
		result->key = key;
		result->digest = CryptoHash::Create(pszAlgId);

		return result;
	}
	CATCH_EXCEPTION;
}

CryptoSign::~CryptoSign()
{
	Destroy();
}

void CryptoSign::Destroy()
{
	if (pszAlgId) {
		free((void*)pszAlgId);
		pszAlgId = NULL;
	}
}

void CryptoSign::Update(PUCHAR pbData, ULONG ulDataLen)
{
	try {
	digest->Update(pbData, ulDataLen);
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> CryptoSign::Final(PVOID pvParams, ULONG ulFlags)
{
	try {
		auto hash = digest->Final();

		ULONG ulSignatureLength;
		Scoped<std::string> result(new std::string(""));

		NTSTATUS status;
		if (status = BCryptSignHash(
			key->Get(),
			pvParams,
			(PUCHAR)hash->c_str(),
			hash->length(),
			NULL,
			0,
			&ulSignatureLength,
			ulFlags
		)) {
			THROW_NT_EXCEPTION(status);
		}
		result->resize(ulSignatureLength);
		if (status = BCryptSignHash(
			key->Get(),
			pvParams,
			(PUCHAR)hash->c_str(),
			hash->length(),
			(PUCHAR)result->c_str(),
			ulSignatureLength,
			&ulSignatureLength,
			ulFlags
		)) {
			THROW_NT_EXCEPTION(status);
		}

		return result;
	}
	CATCH_EXCEPTION;
}
