#pragma once

#include "../stdafx.h"
#include "../core/excep.h"
#include "../core/template.h"
#include <ntstatus.h>

Scoped<std::string> GetErrorString(DWORD code);

#define PRINT_WIN_ERROR() \
    fprintf(stdout, "Error: %s\n", GetErrorString().c_str())

std::string GetNTErrorAsString(NTSTATUS status);

Scoped<std::string> GetLastErrorString();

/**
 * MscapiException
 */

class MscapiException : public core::Pkcs11Exception
{
public:
    MscapiException(
        const char *name,
        int code,
        const char *message,
        const char *function,
        const char *file,
        int line);
};

#define MSCAPI_EXCEPTION_NAME "MSCAPIException"

#define THROW_MSCAPI_CODE_ERROR(expName, msFuncName, dwErrorCode) \
    throw Scoped<core::Exception>(new MscapiException(expName, dwErrorCode, msFuncName, __FUNCTION__, __FILE__, __LINE__))

#define THROW_MSCAPI_EXCEPTION(msFuncName) \
    THROW_MSCAPI_CODE_ERROR(MSCAPI_EXCEPTION_NAME, msFuncName, GetLastError())

#define NT_EXCEPTION_NAME "NTException"

#define THROW_NT_EXCEPTION(status, msFuncName) \
    THROW_MSCAPI_CODE_ERROR(NT_EXCEPTION_NAME, msFuncName, status)

Scoped<CERT_PUBLIC_KEY_INFO> ExportPublicKeyInfo(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey);

NCRYPT_UI_POLICY *new_NCRYPT_UI_POLICY(core::Template *tmpl);
void free_NCRYPT_UI_POLICY(NCRYPT_UI_POLICY *policy);