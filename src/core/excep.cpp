#include "excep.h"

#include <cstdarg>
#include "name.h"

using namespace core;

#define BUFFER_SIZE 1024

Exception::Exception(
    const char*            name,
    const char*            message,
    const char*            function,
    const char*            file,
    int                    line,
    ...
) :
    name(std::string(name)),
    function(std::string(function)),
    file(std::string(file)),
    line(line)
{
    va_list args;
    va_start(args, line);
    char buffer[BUFFER_SIZE];
    vsprintf(buffer, message, args);
    va_end(args);
    this->message = std::string(buffer);
    data = std::string("");
}

void Exception::push(
    Scoped<Exception> item
)
{
    if (stack && stack.get()) {
        stack->push(item);
    }
    else {
        stack = item;
    }
}

char const* Exception::what()
{
    if (!data.length()) {
        // Print data
        data += name + ": ";
        data += message.length() ? message : "No message";
        data += "\n";
        Exception* exception = this;
        while (exception) {
            data += "    at " + exception->function + " (" + exception->file + ":" + std::to_string(exception->line) + ")\n";
            if (exception->stack && exception->stack.get()) {
                exception = exception->stack.get();
            }
            else {
                exception = NULL;
            }
        }
    }
    return data.c_str();
}

/**
 *
 * Pkcs11Exception
 *
 */

Pkcs11Exception::Pkcs11Exception(
    const char*        name,
    CK_ULONG           code,
    const char*        message,
    const char*        function,
    const char*        file,
    int                line,
    ...
) :
    Exception(name, message, function, file, line),
    code(code)
{
    va_list args;
    va_start(args, line);
    char buffer[BUFFER_SIZE] = {0};
    vsprintf(buffer, message, args);
    va_end(args);
    this->message = std::string(buffer);
    
    char buffer2[BUFFER_SIZE] = {0};
    const char* codeStr = Name::getResultValue(code);
    sprintf(buffer2, "%s(0x%08lX) %s", codeStr ? codeStr : "CKR_UNKNOWN", code, this->message.c_str());
    this->message = std::string(buffer2);
    
    if (!name) {
        this->name = PKCS11_EXCEPTION_NAME;
    }
}
