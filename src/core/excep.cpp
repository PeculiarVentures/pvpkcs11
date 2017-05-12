#include "excep.h"

using namespace core;

Exception::Exception(
    const char*            name,
    const char*            message,
    const char*            function,
    const char*            file,
    int                    line
) :
    name(std::string(name)),
    message(std::string(message)),
    function(std::string(function)),
    file(std::string(file)),
    line(line)
{
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
    int                code,
    const char*        message,
    const char*        function,
    const char*        file,
    int                line
) :
    Exception(name, message, function, file, line),
    code(code)
{
    if (!name) {
        this->name = PKCS11_EXCEPTION_NAME;
    }
}