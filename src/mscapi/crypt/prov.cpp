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
	Scoped<Provider> prov(new Provider());
	prov->AcquireContext(szContainer, szProvider, dwProvType, dwFlags);

	return prov;
}

Scoped<Provider> Provider::CreateW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	Scoped<Provider> prov(new Provider());
	prov->AcquireContextW(szContainer, szProvider, dwProvType, dwFlags);

	return prov;
}

void Provider::AcquireContext(
	LPCSTR    szContainer,
	LPCSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	// Remove old provider handle
	this->Destroy();
	if (!CryptAcquireContextA(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
		THROW_MS_ERROR();
	}
}

void Provider::AcquireContextW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
	// Remove old provider handle
	this->Destroy();
	if (!CryptAcquireContextW(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
		THROW_MS_ERROR();
	}
}

void Provider::GetParam(
	DWORD   dwParam,
	BYTE    *pbData,
	DWORD   *pdwDataLen,
	DWORD   dwFlags
)
{
	if (!CryptGetProvParam(this->handle, dwParam, pbData, pdwDataLen, dwFlags)) {
		THROW_MS_ERROR();
	}
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
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
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
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
}

Scoped<std::string> Provider::GetContainer()
{
	try {
		return this->GetBufferParam(PP_CONTAINER);
	}
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
}

Scoped<std::string> Provider::GetName()
{
	try {
		return this->GetBufferParam(PP_NAME);
	}
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
}

DWORD Provider::GetType()
{
	try {
		return this->GetNumberParam(PP_PROVTYPE);
	}
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
}

DWORD Provider::GetKeySpec()
{
	try {
		return this->GetNumberParam(PP_KEYSPEC);
	}
	catch (const Exception &e) {
		THROW_MS_ERROR();
	}
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
	catch (const Exception &e) {
	}
	return res;
}