#include "../bcrypt.h"

using namespace bcrypt;

Key::~Key()
{
	Destroy();
}

void Key::Destroy()
{
	if (handle) {
		BCryptDestroyKey(handle);
		handle = NULL;
	}
}

void Key::Finalize(
	_In_    ULONG   dwFlags
)
{
	NTSTATUS status = BCryptFinalizeKeyPair(handle, dwFlags);
	if (status) {
		THROW_NT_EXCEPTION(status);
	}
}