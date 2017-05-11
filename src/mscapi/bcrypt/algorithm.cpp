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

Scoped<std::string> Algorithm::GenerateRandom(
    ULONG dwLength
)
{
    Scoped<std::string> buf(new std::string(""));
    buf->resize(dwLength);
    PUCHAR pbBuf = (PUCHAR)buf->c_str();
    NTSTATUS status = BCryptGenRandom(NULL, pbBuf, buf->length(), BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
    return buf;
}

Scoped<bcrypt::Key> Algorithm::GenerateKey(
    _Out_writes_bytes_all_opt_(cbKeyObject) PUCHAR  pbKeyObject,
    _In_                                    ULONG   cbKeyObject,
    _In_reads_bytes_(cbSecret)              PUCHAR  pbSecret,
    _In_                                    ULONG   cbSecret,
    _In_                                    ULONG   dwFlags
)
{
    BCRYPT_KEY_HANDLE hKey;

    NTSTATUS status = BCryptGenerateSymmetricKey(
        handle,
        &hKey,
        pbKeyObject,
        cbKeyObject,
        pbSecret,
        cbSecret,
        dwFlags
    );
    if (status) {
        THROW_NT_EXCEPTION(status);
    }

    return Scoped<Key>(new Key(hKey));
}