#include "cng.h"

using namespace cng;

Scoped<CryptoHash> CryptoHash::Create(LPCWSTR pszAlgId)
{
	try {
		Scoped<CryptoHash> res(new CryptoHash());

		res->provider = AlgorithmProvider::Open(pszAlgId, NULL, 0);
		NTSTATUS status = BCryptCreateHash(
			res->provider->Get(),
			&res->handle,
			NULL, 0, NULL, 0, 0
		);

		if (status) {
			THROW_NT_EXCEPTION(status);
		}

		return res;
	}
	CATCH_EXCEPTION;
}

void CryptoHash::Update(PUCHAR pbData, DWORD dwDataLen)
{
	NTSTATUS status = BCryptHashData(handle, pbData, dwDataLen, 0);

	if (status) {
		THROW_NT_EXCEPTION(status);
	}
}

Scoped<std::string> CryptoHash::Final()
{
	try {
		Scoped<std::string> result(new std::string(""));
		result->resize(GetLength());
		NTSTATUS status = BCryptFinishHash(handle, (BYTE*)result->c_str(), result->length(), 0);

		if (status) {
			THROW_NT_EXCEPTION(status);
		}

		return result;
	}
	CATCH_EXCEPTION;
}

void CryptoHash::Destroy()
{
	if (handle) {
		BCryptDestroyHash(handle);
		handle = NULL;
	}
}

DWORD CryptoHash::GetLength()
{
	try {
		return GetNumber(BCRYPT_HASH_LENGTH);
	}
	CATCH_EXCEPTION;
}