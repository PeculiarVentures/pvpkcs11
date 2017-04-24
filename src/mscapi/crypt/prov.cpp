#include "crypt.h"

using namespace crypt;

Provider::Provider()
{
	this->handle = NULL;
}

Provider::Provider(HCRYPTPROV handle)
{
	this->handle = handle;
}

Provider::~Provider()
{
	this->Destroy();
}

HCRYPTPROV Provider::Get()
{
	return handle;
}

void Provider::Set(HCRYPTPROV handle)
{
	if (handle) {
		this->Destroy();
		this->handle = handle;
	}
}

void Provider::Destroy()
{
	this->Destroy(0);
}

void Provider::Destroy(DWORD dwFlags)
{
	if (handle) {
		CryptReleaseContext(handle, dwFlags);
		handle = NULL;
	}
}

Scoped<Provider> Provider::Create(
	LPCSTR    szContainer,
	LPCSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	try {
		Scoped<Provider> prov(new Provider());
		prov->AcquireContext(szContainer, szProvider, dwProvType, dwFlags);

		return prov;
	}
	CATCH_EXCEPTION;
}

Scoped<Provider> Provider::CreateW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	try {
		Scoped<Provider> prov(new Provider());
		prov->AcquireContextW(szContainer, szProvider, dwProvType, dwFlags);

		return prov;
	}
	CATCH_EXCEPTION;
}

void Provider::AcquireContext(
	LPCSTR    szContainer,
	LPCSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	try {
		// Remove old provider handle
		this->Destroy();
		if (!CryptAcquireContextA(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

void Provider::AcquireContextW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	try {
		// Remove old provider handle
		this->Destroy();
		if (!CryptAcquireContextW(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

void Provider::GetParam(
	DWORD   dwParam,
	BYTE    *pbData,
	DWORD   *pdwDataLen,
	DWORD   dwFlags
)
{
	try {
		if (!CryptGetProvParam(this->handle, dwParam, pbData, pdwDataLen, dwFlags)) {
			THROW_MSCAPI_ERROR();
		}
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Provider::GetBufferParam(
	DWORD   dwParam,
	DWORD   dwFlag
)
{
	try {
		Scoped<std::string> result(new std::string());
		DWORD dwDataLen;
		this->GetParam(dwParam, NULL, &dwDataLen, 0);
		if (dwDataLen) {
			result->resize(dwDataLen);
			this->GetParam(dwParam, (BYTE*)result->c_str(), &dwDataLen, dwFlag);
		}
		return result;
	}
	CATCH_EXCEPTION;
}

DWORD Provider::GetNumberParam(
	DWORD   dwParam
)
{
	try {
		DWORD result;
		DWORD dwDataLen = sizeof(DWORD);
		this->GetParam(dwParam, (BYTE*)&result, &dwDataLen, 0);

		return result;
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Provider::GetContainer()
{
	try {
		return this->GetBufferParam(PP_CONTAINER);
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Provider::GetName()
{
	try {
		return this->GetBufferParam(PP_NAME);
	}
	CATCH_EXCEPTION;
}

DWORD Provider::GetType()
{
	try {
		return this->GetNumberParam(PP_PROVTYPE);
	}
	CATCH_EXCEPTION;
}

DWORD Provider::GetKeySpec()
{
	try {
		return this->GetNumberParam(PP_KEYSPEC);
	}
	CATCH_EXCEPTION;
}

Scoped<Collection<Scoped<std::string>>> Provider::GetContainers()
{
	Scoped<Collection<Scoped<std::string>>> res(new Collection<Scoped<std::string>>());
	try {
		while (true) {
			Scoped<std::string> container = this->GetBufferParam(PP_ENUMCONTAINERS, res->count() ? CRYPT_NEXT : CRYPT_FIRST);
			res->add(container);
		}
	}
	catch (Scoped<core::Exception>) {
		// Ignore last exception
	}
	return res;
}