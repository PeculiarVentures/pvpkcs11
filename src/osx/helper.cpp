#include "helper.h"

#include <Security/Security.h>

using namespace osx;

std::string osx::GetOSXErrorAsString
(
 OSStatus status,
 const char* funcName
 )
{
    CFRef<CFStringRef> osxMessage = SecCopyErrorMessageString(status, NULL);
    
    char message[1024];
    sprintf(message, "Error on %s %d. %s", funcName, status, CFStringGetCStringPtr(&osxMessage, kCFStringEncodingUTF8));
    
    return std::string(message, strlen(message));
}
