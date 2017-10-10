#include "excep.h"

#include <cstdarg>

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

const char* getPkcs11ResultName(CK_RV value) {
#define CASE(name)  \
case name:          \
    return #name
    
    switch (value) {
        CASE(CKR_OK);
        CASE(CKR_CANCEL);
        CASE(CKR_HOST_MEMORY);
        CASE(CKR_SLOT_ID_INVALID);
        CASE(CKR_GENERAL_ERROR);
        CASE(CKR_FUNCTION_FAILED);
        CASE(CKR_ARGUMENTS_BAD);
        CASE(CKR_NO_EVENT);
        CASE(CKR_NEED_TO_CREATE_THREADS);
        CASE(CKR_CANT_LOCK);
        CASE(CKR_ATTRIBUTE_READ_ONLY);
        CASE(CKR_ATTRIBUTE_SENSITIVE);
        CASE(CKR_ATTRIBUTE_TYPE_INVALID);
        CASE(CKR_ATTRIBUTE_VALUE_INVALID);
        CASE(CKR_DATA_INVALID);
        CASE(CKR_DATA_LEN_RANGE);
        CASE(CKR_DEVICE_ERROR);
        CASE(CKR_DEVICE_MEMORY);
        CASE(CKR_DEVICE_REMOVED);
        CASE(CKR_ENCRYPTED_DATA_INVALID);
        CASE(CKR_ENCRYPTED_DATA_LEN_RANGE);
        CASE(CKR_FUNCTION_CANCELED);
        CASE(CKR_FUNCTION_NOT_PARALLEL);
        CASE(CKR_FUNCTION_NOT_SUPPORTED);
        CASE(CKR_KEY_HANDLE_INVALID);
        CASE(CKR_KEY_SIZE_RANGE);
        CASE(CKR_KEY_TYPE_INCONSISTENT);
        CASE(CKR_KEY_NOT_NEEDED);
        CASE(CKR_KEY_CHANGED);
        CASE(CKR_KEY_NEEDED);
        CASE(CKR_KEY_INDIGESTIBLE);
        CASE(CKR_KEY_FUNCTION_NOT_PERMITTED);
        CASE(CKR_KEY_NOT_WRAPPABLE);
        CASE(CKR_KEY_UNEXTRACTABLE);
        CASE(CKR_MECHANISM_INVALID);
        CASE(CKR_MECHANISM_PARAM_INVALID);
        CASE(CKR_OBJECT_HANDLE_INVALID);
        CASE(CKR_OPERATION_ACTIVE);
        CASE(CKR_OPERATION_NOT_INITIALIZED);
        CASE(CKR_PIN_INCORRECT);
        CASE(CKR_PIN_INVALID);
        CASE(CKR_PIN_LEN_RANGE);
        CASE(CKR_PIN_EXPIRED);
        CASE(CKR_PIN_LOCKED);
        CASE(CKR_SESSION_CLOSED);
        CASE(CKR_SESSION_COUNT);
        CASE(CKR_SESSION_HANDLE_INVALID);
        CASE(CKR_SESSION_PARALLEL_NOT_SUPPORTED);
        CASE(CKR_SESSION_READ_ONLY);
        CASE(CKR_SESSION_EXISTS);
        CASE(CKR_SESSION_READ_ONLY_EXISTS);
        CASE(CKR_SESSION_READ_WRITE_SO_EXISTS);
        CASE(CKR_SIGNATURE_INVALID);
        CASE(CKR_SIGNATURE_LEN_RANGE);
        CASE(CKR_TEMPLATE_INCOMPLETE);
        CASE(CKR_TEMPLATE_INCONSISTENT);
        CASE(CKR_TOKEN_NOT_PRESENT);
        CASE(CKR_TOKEN_NOT_RECOGNIZED);
        CASE(CKR_TOKEN_WRITE_PROTECTED);
        CASE(CKR_UNWRAPPING_KEY_HANDLE_INVALID);
        CASE(CKR_UNWRAPPING_KEY_SIZE_RANGE);
        CASE(CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT);
        CASE(CKR_USER_ALREADY_LOGGED_IN);
        CASE(CKR_USER_NOT_LOGGED_IN);
        CASE(CKR_USER_PIN_NOT_INITIALIZED);
        CASE(CKR_USER_TYPE_INVALID);
        CASE(CKR_USER_ANOTHER_ALREADY_LOGGED_IN);
        CASE(CKR_USER_TOO_MANY_TYPES);
        CASE(CKR_WRAPPED_KEY_INVALID);
        CASE(CKR_WRAPPED_KEY_LEN_RANGE);
        CASE(CKR_WRAPPING_KEY_HANDLE_INVALID);
        CASE(CKR_WRAPPING_KEY_SIZE_RANGE);
        CASE(CKR_WRAPPING_KEY_TYPE_INCONSISTENT);
        CASE(CKR_RANDOM_SEED_NOT_SUPPORTED);
        CASE(CKR_RANDOM_NO_RNG);
        CASE(CKR_DOMAIN_PARAMS_INVALID);
        CASE(CKR_BUFFER_TOO_SMALL);
        CASE(CKR_SAVED_STATE_INVALID);
        CASE(CKR_INFORMATION_SENSITIVE);
        CASE(CKR_STATE_UNSAVEABLE);
        CASE(CKR_CRYPTOKI_NOT_INITIALIZED);
        CASE(CKR_CRYPTOKI_ALREADY_INITIALIZED);
        CASE(CKR_MUTEX_BAD);
        CASE(CKR_MUTEX_NOT_LOCKED);
        CASE(CKR_NEW_PIN_MODE);
        CASE(CKR_NEXT_OTP);
        CASE(CKR_EXCEEDED_MAX_ITERATIONS);
        CASE(CKR_FIPS_SELF_TEST_FAILED);
        CASE(CKR_LIBRARY_LOAD_FAILED);
        CASE(CKR_PIN_TOO_WEAK);
        CASE(CKR_PUBLIC_KEY_INVALID);
        CASE(CKR_FUNCTION_REJECTED);
        default:
            return "CKR_UNKNOWN";
    }
#undef CASE
}

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
    sprintf(buffer2, "%s(0x%08lX) %s", getPkcs11ResultName(code), code, this->message.c_str());
    this->message = std::string(buffer2);
    
    if (!name) {
        this->name = PKCS11_EXCEPTION_NAME;
    }
}
