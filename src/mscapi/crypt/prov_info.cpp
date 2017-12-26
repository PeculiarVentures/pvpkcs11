#include "prov_info.h"

#include "../helper.h"

using namespace crypt;

NTSTATUS FreeKey(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle) {
    if (NCryptIsKeyHandle(handle)) {
        return NCryptFreeObject(handle);
    }
    else {
        if (!CryptReleaseContext(handle, 0)) {
            return GetLastError();
        }
    }
    return ERROR_SUCCESS;
}

NTSTATUS OpenKey(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE* handle, PCRYPT_KEY_PROV_INFO provInfo, BOOL fSilent) {
    if (provInfo->dwProvType) {
        // CAPI
        if (!CryptAcquireContextW(handle, provInfo->pwszContainerName, provInfo->pwszProvName, provInfo->dwProvType, fSilent ? CRYPT_SILENT : 0)) {
            return GetLastError();
        }
    }
    else {
        // CNG
        NTSTATUS status = ERROR_SUCCESS;
        NCRYPT_PROV_HANDLE hProv = 0;

        while (true) {
            status = NCryptOpenStorageProvider(&hProv, provInfo->pwszProvName, 0);
            if (status) {
                break;
            }

            status = NCryptOpenKey(hProv, handle, provInfo->pwszContainerName, provInfo->dwKeySpec, fSilent ? NCRYPT_SILENT_FLAG : 0);
            if (status) {
                break;
            }

            break;
        }

        if (hProv) {
            NCryptFreeObject(hProv);
        }

        return status;
    }
    return ERROR_SUCCESS;
}

ProviderInfo::ProviderInfo(Scoped<Buffer> info) :
    buffer(info),
    info((CRYPT_KEY_PROV_INFO*)info->data())
{
}


ProviderInfo::~ProviderInfo()
{
}

bool crypt::ProviderInfo::IsAccassible()
{
    HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
    NTSTATUS status = ERROR_SUCCESS;
    status = OpenKey(&handle, info, true);
    if (status) {
        return false;
    }
    return true;
}

CRYPT_KEY_PROV_INFO * ProviderInfo::Get()
{
    return info;
}

Scoped<Buffer> crypt::ProviderInfo::GetSmartCardGUID()
{
    try {
        return GetBytes(PP_SMARTCARD_GUID);
    }
    CATCH_EXCEPTION
}

Scoped<std::string> crypt::ProviderInfo::GetSmartCardReader()
{
    try {
        auto buf = GetBytes(PP_SMARTCARD_READER);
        return Scoped<std::string>(new std::string((PCHAR)buf->data()));
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> crypt::ProviderInfo::GetBytes(DWORD dwParam)
{
    try {
        HCRYPTPROV_OR_NCRYPT_KEY_HANDLE handle = 0;
        NTSTATUS status = 0;
        Scoped<Buffer> res(new Buffer(0));

        status = OpenKey(&handle, info, true);
        if (status) {
            THROW_NT_EXCEPTION(status, "OpenKey");
        }
        
        if (NCryptIsKeyHandle(handle)) {
            // CNG
            LPCWSTR propID;
            switch (dwParam) {
            case PP_SMARTCARD_GUID:
                propID = NCRYPT_SMARTCARD_GUID_PROPERTY;
                break;
            case PP_SMARTCARD_READER:
                propID = NCRYPT_READER_PROPERTY;
                break;
            default:
                FreeKey(handle);
                THROW_EXCEPTION("Unsupported property of Provider dwParam:%d", dwParam);
            }
            DWORD dataLen = 0;
            status = NCryptGetProperty(handle, propID, NULL, 0, &dataLen, 0);
            if (status) {
                FreeKey(handle);
                THROW_MSCAPI_CODE_ERROR(MSCAPI_EXCEPTION_NAME, "CryptGetProvParam", status);
            }
            res->resize(dataLen);
            status = NCryptGetProperty(handle, propID, res->data(), res->size(), &dataLen, 0);
            if (status) {
                FreeKey(handle);
                THROW_MSCAPI_CODE_ERROR(MSCAPI_EXCEPTION_NAME, "CryptGetProvParam", status);
            }
        }
        else {
            // CAPI
            DWORD dataLen = 0;
            if (!CryptGetProvParam(handle, dwParam, NULL, &dataLen, 0)) {
                status = GetLastError();
                FreeKey(handle);
                THROW_MSCAPI_CODE_ERROR(MSCAPI_EXCEPTION_NAME, "CryptGetProvParam", status);
            }
            res->resize(dataLen);
            if (!CryptGetProvParam(handle, dwParam, res->data(), &dataLen, 0)) {
                status = GetLastError();
                FreeKey(handle);
                THROW_MSCAPI_CODE_ERROR(MSCAPI_EXCEPTION_NAME, "CryptGetProvParam", status);
            }
        }

        return res;
    }
    CATCH_EXCEPTION
}
