#include "helper.h"

typedef struct _NT_STATUS_MESSAGE
{
    ULONG ulStatus;
    PCHAR pMessage;
} NT_STATUS_MESSAGE;

NT_STATUS_MESSAGE NT_STATUS_MESSAGES[] = {
    {0, "The operation completed successfully."},
    {STATUS_INVALID_HANDLE, "An invalid HANDLE was specified"},
    {STATUS_BUFFER_TOO_SMALL, "The buffer is too small to contain the entry"},
    {STATUS_INVALID_PARAMETER, "One or more parameters are not valid."},
    {STATUS_NO_MEMORY, "A memory allocation failure occurred."},
    {STATUS_NOT_SUPPORTED, "The request is not supported."},
    {STATUS_DATA_ERROR, "An error occurred in reading or writing data."},
    {STATUS_NOT_FOUND, "The object was not found"},
    {NTE_INVALID_HANDLE, "The supplied handle is invalid."},
    {NTE_BAD_ALGID, "Wrong algorithm identity."},
    {NTE_BAD_FLAGS, "Wrong flags value."},
    {NTE_INVALID_PARAMETER, "One or more parameters are not valid."},
    {NTE_NO_MEMORY, "A memory allocation failure occurred."},
    {NTE_NOT_SUPPORTED, "The specified property is not supported for the object."},
    {NTE_PERM, "Access denied."},
    {NTE_NO_MORE_ITEMS, "The end of the enumeration has been reached."},
    {NTE_SILENT_CONTEXT, "The dwFlags parameter contains the NCRYPT_SILENT_FLAG flag, but the key being enumerated requires user interaction."},
    {NTE_BAD_TYPE, "Invalid type specified."}};

std::string GetNTErrorAsString(NTSTATUS status)
{
    std::string hexCode("");
    hexCode.resize(sizeof(status) * 2);
    sprintf((PCHAR)hexCode.c_str(), "%X", status);
    ULONG ulMessagesCount = sizeof(NT_STATUS_MESSAGES) / sizeof(NT_STATUS_MESSAGE);
    std::string message("Unknown message");
    for (int i = 0; i < ulMessagesCount; i++)
    {
        if (NT_STATUS_MESSAGES[i].ulStatus == status)
        {
            message = std::string(NT_STATUS_MESSAGES[i].pMessage);
            break;
        }
    }
    return "(" + hexCode + ") " + message;
}

std::string ReplaceAll(const char *str, const char *from, const char *to)
{
    size_t start_pos = 0;
    std::string res(str);
    std::string fromStr(from);
    std::string toStr(to);

    while ((start_pos = res.find(fromStr, start_pos)) != std::string::npos)
    {
        res.replace(start_pos, fromStr.length(), to);
        start_pos += toStr.length();
    }

    return res;
}

Scoped<std::string> GetErrorString(DWORD code)
{
    Scoped<std::string> result(new std::string);
    // Get the error message, if any.
    if (code == 0)
    {
        *result.get() += "No error message";
    }
    else
    {
        LPSTR messageBuffer = nullptr;
        size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                                     NULL, code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

        if (messageBuffer)
        {
            std::string message(messageBuffer);

            // Free the buffer.
            LocalFree(messageBuffer);

            // remove \n\r from message
            message = ReplaceAll(message.c_str(), "\n", "");
            message = ReplaceAll(message.c_str(), "\r", "");

            *result += message;
        }
        else
        {
            char buf[256] = {0};
            sprintf(buf, "Error code 0x%08lX", code);
            *result.get() += std::string(buf);
        }
    }

    return result;
}

Scoped<std::string> GetLastErrorString()
{
    DWORD dwErrorCode = GetLastError();
    return GetErrorString(dwErrorCode);
}

Scoped<CERT_PUBLIC_KEY_INFO> ExportPublicKeyInfo(HCRYPTPROV_OR_NCRYPT_KEY_HANDLE hKey)
{
    LOGGER_FUNCTION_BEGIN;

    try
    {
        ULONG spkiLen;
        if (!CryptExportPublicKeyInfo(
                hKey,
                0,
                X509_ASN_ENCODING,
                NULL,
                &spkiLen))
        {
            THROW_MSCAPI_EXCEPTION("CryptExportPublicKeyInfo");
        }
        PCERT_PUBLIC_KEY_INFO pSpki = (PCERT_PUBLIC_KEY_INFO)malloc(spkiLen);
        if (!CryptExportPublicKeyInfo(
                hKey,
                0,
                X509_ASN_ENCODING,
                pSpki,
                &spkiLen))
        {
            THROW_MSCAPI_EXCEPTION("CryptExportPublicKeyInfo");
        }
        return Scoped<CERT_PUBLIC_KEY_INFO>(pSpki, free);
    }
    CATCH_EXCEPTION
}

MscapiException::MscapiException(
    const char *name,
    int code,
    const char *message,
    const char *function,
    const char *file,
    int line) : Pkcs11Exception(name,
                                code,
                                message,
                                function,
                                file,
                                line)
{
    char buf[32] = {0};
    sprintf(buf, "(0x%08lX)", code);
    this->message = name + std::string(buf) + std::string(" ") + message + std::string(" ") + *GetErrorString(code);
};

LPCWSTR new_LPCWSTR(const char *chars)
{
    if (chars == NULL)
    {
        return NULL;
    }

    auto wstrSize = MultiByteToWideChar(CP_UTF8, 0, chars, strlen(chars), NULL, 0);
    LPWSTR wString = (LPWSTR)calloc(wstrSize + 1, sizeof(WCHAR));
    MultiByteToWideChar(CP_UTF8, 0, chars, strlen(chars), wString, wstrSize);

    return wString;
}

void free_LPCWSTR(LPCWSTR str)
{
    if (str != NULL)
    {
        free(LPWSTR(str));
    }
}

NCRYPT_UI_POLICY *new_NCRYPT_UI_POLICY(core::Template *tmpl)
{
    LOGGER_FUNCTION_BEGIN;

    try
    {
        NCRYPT_UI_POLICY *policy;
        auto dwFlags = tmpl->GetNumber(CKA_PIN_FLAGS, false, 0);
        auto pszCreationTitle = tmpl->GetString(CKA_PIN_CREATION_TITLE, false);
        auto pszDescription = tmpl->GetString(CKA_PIN_DESCRIPTION, false);
        auto pszFriendlyName = tmpl->GetString(CKA_PIN_FRIENDLY_NAME, false);

        policy = (NCRYPT_UI_POLICY *)malloc(sizeof(NCRYPT_UI_POLICY));
        policy->dwVersion = 1;
        policy->dwFlags = tmpl->GetNumber(CKA_PIN_FLAGS, false, 0);
        policy->pszCreationTitle = new_LPCWSTR(pszCreationTitle->c_str());
        policy->pszDescription = new_LPCWSTR(pszDescription->c_str());
        policy->pszFriendlyName = new_LPCWSTR(pszFriendlyName->c_str());

        return policy;
    }
    CATCH_EXCEPTION
}

void free_NCRYPT_UI_POLICY(NCRYPT_UI_POLICY *policy)
{
    if (policy != NULL)
    {
        free_LPCWSTR(policy->pszCreationTitle);
        free_LPCWSTR(policy->pszDescription);
        free_LPCWSTR(policy->pszFriendlyName);
        free(policy);

        policy = NULL;
    }
}