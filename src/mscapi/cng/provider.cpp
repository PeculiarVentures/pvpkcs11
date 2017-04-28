#include "cng.h"

using namespace cng;

AlgorithmProvider::AlgorithmProvider(BCRYPT_ALG_HANDLE handle)
{
	this->handle = handle;
}

void AlgorithmProvider::Destroy()
{
	if (handle) {
		BCryptCloseAlgorithmProvider(handle, 0);
		handle = NULL;
	}
}

Scoped<AlgorithmProvider> AlgorithmProvider::Open(
	_In_        LPCWSTR pszAlgId,
	_In_opt_    LPCWSTR pszImplementation,
	_In_        ULONG   dwFlags
)
{
	BCRYPT_ALG_HANDLE hAlg;

	NTSTATUS status = BCryptOpenAlgorithmProvider(
		&hAlg,
		pszAlgId,
		pszImplementation,
		dwFlags
	);

	if (status) {
		THROW_NT_EXCEPTION(status);
	}

	return Scoped<AlgorithmProvider>(new AlgorithmProvider(hAlg));
}