#include "crypt.h"

#include <xstring>

using namespace crypt;

crypt::Provider::Provider()
{
    LOGGER_FUNCTION_BEGIN;

	this->handle = NULL;
}

crypt::Provider::Provider(HCRYPTPROV handle)
{
    LOGGER_FUNCTION_BEGIN;

	this->handle = handle;
}

crypt::Provider::~Provider()
{
    LOGGER_FUNCTION_BEGIN;

	this->Destroy();
}

HCRYPTPROV crypt::Provider::Get()
{
    LOGGER_FUNCTION_BEGIN;

	return handle;
}

void crypt::Provider::Set(HCRYPTPROV handle)
{
    LOGGER_FUNCTION_BEGIN;

	if (handle) {
		this->Destroy();
		this->handle = handle;
	}
}

void crypt::Provider::Destroy()
{
    LOGGER_FUNCTION_BEGIN;

	this->Destroy(0);
}

void crypt::Provider::Destroy(DWORD dwFlags)
{
    LOGGER_FUNCTION_BEGIN;

    if (handle) {
        LOGGER_TRACE("%s %s", __FUNCTION__, "CryptReleaseContext");
        LOGGER_DEBUG("%s handle:%p dwFlags:%d", __FUNCTION__, handle, dwFlags);
        if (!CryptReleaseContext(handle, dwFlags)) {
            THROW_MSCAPI_EXCEPTION("CryptReleaseContext");
        }
	    handle = NULL;
    }
}

Scoped<Provider> crypt::Provider::Create(
	LPCSTR    szContainer,
	LPCSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		Scoped<Provider> prov(new Provider());
		prov->AcquireContext(szContainer, szProvider, dwProvType, dwFlags);

		return prov;
	}
	CATCH_EXCEPTION;
}

Scoped<Provider> crypt::Provider::CreateW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		Scoped<Provider> prov(new Provider());
		prov->AcquireContextW(szContainer, szProvider, dwProvType, dwFlags);

		return prov;
	}
	CATCH_EXCEPTION;
}

void crypt::Provider::AcquireContext(
	LPCSTR    szContainer,
	LPCSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		// Remove old provider handle
		this->Destroy();
		if (!CryptAcquireContextA(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
			THROW_MSCAPI_EXCEPTION("CryptAcquireContextA");
		}
	}
	CATCH_EXCEPTION;
}

void crypt::Provider::AcquireContextW(
	LPWSTR    szContainer,
	LPWSTR    szProvider,
	DWORD     dwProvType,
	DWORD     dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		// Remove old provider handle
		this->Destroy();

        std::wstring wstrContainer(szContainer);
        std::wstring wstrProvider(szProvider);

        LOGGER_DEBUG("%s CryptAcquireContextW szContainer:'%s' szProvider:'%s' dwProvType:%d dwFlags:%d", 
            __FUNCTION__,
            std::string(wstrContainer.begin(), wstrContainer.end()).c_str(),
            std::string(wstrProvider.begin(), wstrProvider.end()).c_str(),
            dwProvType,
            dwFlags
        );

		if (!CryptAcquireContextW(&this->handle, szContainer, szProvider, dwProvType, dwFlags)) {
			THROW_MSCAPI_EXCEPTION("CryptAcquireContextW");
		}
        LOGGER_DEBUG("%s After CryptAcquireContextW", __FUNCTION__);
	}
	CATCH_EXCEPTION;
}

void crypt::Provider::GetParam(
	DWORD   dwParam,
	BYTE    *pbData,
	DWORD   *pdwDataLen,
	DWORD   dwFlags
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		if (!CryptGetProvParam(this->handle, dwParam, pbData, pdwDataLen, dwFlags)) {
			THROW_MSCAPI_EXCEPTION("CryptGetProvParam");
		}
	}
	CATCH_EXCEPTION;
}

Scoped<Buffer> crypt::Provider::GetBufferParam(
	DWORD   dwParam,
	DWORD   dwFlag
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		Scoped<Buffer> result(new Buffer());
		DWORD dwDataLen;
		this->GetParam(dwParam, NULL, &dwDataLen, 0);
		if (dwDataLen) {
			result->resize(dwDataLen);
			this->GetParam(dwParam, result->data(), &dwDataLen, dwFlag);
		}
		return result;
	}
	CATCH_EXCEPTION;
}

DWORD crypt::Provider::GetNumberParam(
	DWORD   dwParam
)
{
    LOGGER_FUNCTION_BEGIN;

	try {
		DWORD result;
		DWORD dwDataLen = sizeof(DWORD);
		this->GetParam(dwParam, (BYTE*)&result, &dwDataLen, 0);

		return result;
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> crypt::Provider::GetContainer()
{
    LOGGER_FUNCTION_BEGIN;

	try {
		return Scoped<std::string>(new std::string((char*)GetBufferParam(PP_CONTAINER)->data()));
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> crypt::Provider::GetName()
{
    LOGGER_FUNCTION_BEGIN;

	try {
		return Scoped<std::string>(new std::string((char*)GetBufferParam(PP_NAME)->data()));
	}
	CATCH_EXCEPTION;
}

DWORD crypt::Provider::GetType()
{
    LOGGER_FUNCTION_BEGIN;

	try {
		return this->GetNumberParam(PP_PROVTYPE);
	}
	CATCH_EXCEPTION;
}

DWORD crypt::Provider::GetKeySpec()
{
    LOGGER_FUNCTION_BEGIN;

	try {
		return this->GetNumberParam(PP_KEYSPEC);
	}
	CATCH_EXCEPTION;
}

Scoped<Buffer> crypt::Provider::GetSmartCardGUID()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return GetBufferParam(PP_SMARTCARD_GUID, 0);
    }
    CATCH_EXCEPTION
}

std::vector<Scoped<std::string>> crypt::Provider::GetContainers()
{
    LOGGER_FUNCTION_BEGIN;

	std::vector<Scoped<std::string> > res;
	try {
		while (true) {
			Scoped<std::string> container(new std::string((char*)GetBufferParam(PP_ENUMCONTAINERS, res.size() ? CRYPT_NEXT : CRYPT_FIRST)->data()));
			res.push_back(container);
		}
	}
	catch (Scoped<core::Exception> e) {
        LOGGER_ERROR("%s Ignore last exception. %s", __FUNCTION__, e->message.c_str());
	}
	return res;
}

Scoped<Key> crypt::Provider::GetUserKey(
    DWORD           dwKeySpec
)
{
    LOGGER_FUNCTION_BEGIN;

    HCRYPTKEY hKey;
    if (!CryptGetUserKey(handle, dwKeySpec, &hKey)) {
        THROW_MSCAPI_EXCEPTION("CryptGetUserKey");
    }
    return Scoped<Key>(new Key(hKey));
}

CK_BBOOL crypt::Provider::HasParam(DWORD dwParam)
{
    LOGGER_FUNCTION_BEGIN;

    DWORD dwDataLen = 0;

    return !CryptGetProvParam(handle, dwParam, NULL, &dwDataLen, 0);
}