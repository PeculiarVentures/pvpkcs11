#include "cng.h"

using namespace cng;

Scoped<AsymmetricKey> AsymmetricKey::GenerateKeyPair(
	Scoped<AlgorithmProvider> algorithm,
	ULONG ulLength,
	ULONG ulFlags
)
{
	try {
		BCRYPT_KEY_HANDLE hNewKey;

		NTSTATUS status;
		if (status = BCryptGenerateKeyPair(
			algorithm->Get(),
			&hNewKey,
			ulLength,
			ulFlags
		)) {
			THROW_NT_EXCEPTION(status);
		}

		Scoped<AsymmetricKey> result(new AsymmetricKey(hNewKey));
		result->Finalise();
		return result;
	}
	CATCH_EXCEPTION;
}

void AsymmetricKey::Finalise()
{
	try {
		NTSTATUS status;
		if (status = BCryptFinalizeKeyPair(handle, 0)) {
			THROW_NT_EXCEPTION(status);
		}
	}
	CATCH_EXCEPTION;
}