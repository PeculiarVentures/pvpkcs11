#include "crypt.h"

using namespace crypt;

Scoped<std::string> GetLastErrorAsString(DWORD code)
{
	Scoped<std::string> result(new std::string);
	//Get the error message, if any.
	if (code == 0) {
		*result.get() += "No error message";
	}
	else {
		LPSTR messageBuffer = nullptr;
		size_t size = FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
			NULL, code, MAKELANGID(LANG_ENGLISH, SUBLANG_DEFAULT), (LPSTR)&messageBuffer, 0, NULL);

		std::string message(messageBuffer, size);

		//Free the buffer.
		LocalFree(messageBuffer);

		*result += message;
	}

	return result;
}

Exception::Exception(
	const char*        name,
	int                code,
	const char*        message,
	const char*        function,
	const char*        file,
	int                line
) : Pkcs11Exception(
	name,
	code,
	message,
	function,
	file,
	line
) {
	this->message = *GetLastErrorAsString(code);
};