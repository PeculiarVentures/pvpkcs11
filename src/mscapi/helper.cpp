#include "helper.h"

std::string GetLastErrorAsString()
{
	//Get the error message, if any.
	DWORD errorMessageID = GetLastError();
	fprintf(stdout, "Error No: %u\n", errorMessageID);
	if (errorMessageID == 0)
		return std::string(); //No error message has been recorded

	LPSTR messageBuffer = nullptr;
	size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, errorMessageID, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

	std::string message(messageBuffer, size);

	//Free the buffer.
	LocalFree(messageBuffer);

	return message;
}

typedef struct _NT_STATUS_MESSAGE {
	ULONG ulStatus;
	PCHAR pMessage;
} NT_STATUS_MESSAGE;

NT_STATUS_MESSAGE NT_STATUS_MESSAGES[] = {
	{ 0, "The operation completed successfully." },
	{ NTE_INVALID_HANDLE, "An invalid HANDLE was specified" },
	{ NTE_BUFFER_TOO_SMALL, "The buffer is too small to contain the entry" },
	{ NTE_INVALID_PARAMETER, "One or more parameters are not valid." },
	{ NTE_NO_MEMORY, "A memory allocation failure occurred." },
	{ NTE_NOT_SUPPORTED, "The request is not supported." },
	{ NTE_BAD_ALGID, "Wrong algorithm identity." },
	{ NTE_BAD_FLAGS, "Wrong flags value." },
};

std::string GetNTErrorAsString(NTSTATUS status)
{
	ULONG ulMessagesCount = sizeof(NT_STATUS_MESSAGES) / sizeof(NT_STATUS_MESSAGE);
	for (int i = 0; i < ulMessagesCount; i++) {
		if (NT_STATUS_MESSAGES[i].ulStatus == status) {
			return std::string(NT_STATUS_MESSAGES[i].pMessage);
		}
	}
	return std::string("Unknown message");
}