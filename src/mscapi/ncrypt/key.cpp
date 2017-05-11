#include "../ncrypt.h"

using namespace ncrypt;

Key::Key(
    NCRYPT_KEY_HANDLE handle
)
{
    this->handle = handle;
}

Key::~Key()
{
    if (handle) {
        NCryptFreeObject(handle);
        handle = NULL;
    }
}

void Key::Finalize(
    ULONG dwFlags
)
{
    NTSTATUS status = NCryptFinalizeKey(handle, dwFlags);
    if (status) {
        THROW_NT_EXCEPTION(status);
    }
}