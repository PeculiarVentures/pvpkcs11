#include "helper.h"

using namespace osx;

std::string osx::GetOSXErrorAsString
(
 OSStatus status,
 const char* funcName
 )
{
    CFRef<CFStringRef> osxMessage = SecCopyErrorMessageString(status, NULL);
    
    char message[1024];
    sprintf(message, "Error on %s %d. %s", funcName, status, CFStringGetCStringPtr(*osxMessage, kCFStringEncodingUTF8));
    
    return std::string(message, strlen(message));
}


CK_RV osx::SecItemDestroy(void *item)
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        OSStatus status;
        THROW_EXCEPTION("Not implemented");
    }
    CATCH_EXCEPTION
}
