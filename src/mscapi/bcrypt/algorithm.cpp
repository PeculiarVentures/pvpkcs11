#include "../bcrypt.h"

using namespace bcrypt;

Algorithm::~Algorithm()
{
	if (handle) {
		BCryptCloseAlgorithmProvider(handle, 0);
		handle = NULL;
	}
}

void Algorithm::Open(
	_In_        LPCWSTR              pszAlgId,
	_In_opt_    LPCWSTR              pszImplementation,
	_In_        ULONG                dwFlags
)
{
	NTSTATUS status = BCryptOpenAlgorithmProvider(&handle, pszAlgId, pszImplementation, dwFlags);
	if (status) {
		THROW_NT_EXCEPTION(status);
	}
}

Scoped<Key> Algorithm::GenerateKeyPair(
	_In_    ULONG   dwLength,
	_In_    ULONG   dwFlags
)
{
	Scoped<Key> key(new Key());
	auto hKey = key->Get();
	NTSTATUS status = BCryptGenerateKeyPair(handle, &hKey, dwLength, dwFlags);

	return key;
}