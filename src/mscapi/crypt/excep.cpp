#include "crypt.h"

using namespace crypt;

static Scoped<std::string> GetLastErrorAsString(DWORD code)
{
	Scoped<std::string> result(new std::string("MSCAPI:Error: "));
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

Exception::Exception(const DWORD code, const char* funcName) :
	std::exception(),
	code(code),
	functionName(funcName)
{
	this->message = GetLastErrorAsString(code);
}

char const* Exception::what() const {
	return this->message->c_str();
}