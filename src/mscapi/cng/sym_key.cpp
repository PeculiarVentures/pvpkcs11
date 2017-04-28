#include "cng.h"

using namespace cng;

Scoped<SymmetricKey> SymmetricKey::GenerateKey(Scoped<AlgorithmProvider> algorithm)
{
	BCRYPT_KEY_HANDLE hNewKey;

	NTSTATUS status;
	if (status = BCryptGenerateSymmetricKey(
		algorithm->Get(),
		&hNewKey,
		NULL, 0,
		NULL, 0,
		0
	)) {
		THROW_NT_EXCEPTION(status);
	}

	return Scoped<SymmetricKey>(new SymmetricKey(hNewKey));
}

Scoped<std::wstring> CryptoKey::GetAlgorithmName()
{
	try {
		return GetBytesW(BCRYPT_ALGORITHM_NAME);
	}
	CATCH_EXCEPTION;
}