#include "crypt.h"

using namespace crypt;

std::string ReplaceAll(const char* str, const char* from, const char* to) {
    size_t start_pos = 0;
    std::string res(str);
    std::string fromStr(from);
    std::string toStr(to);

    while ((start_pos = res.find(fromStr, start_pos)) != std::string::npos) {
        res.replace(start_pos, fromStr.length(), to);
        start_pos += toStr.length();
    }
    
    return res;
}

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

		std::string message(messageBuffer);

		// Free the buffer.
		LocalFree(messageBuffer);

        // remove \n\r from message
        message = ReplaceAll(message.c_str(), "\n", "");
        message = ReplaceAll(message.c_str(), "\r", "");

		*result += message;
	}

	return result;
}

Scoped<std::string> GetLastErrorString()
{
    DWORD dwErrorCode = GetLastError();
    return GetLastErrorAsString(dwErrorCode);
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
	this->message = name + std::string(" ") + message + std::string(" ") + *GetLastErrorAsString(code);
};