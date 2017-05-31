#include "session.h"

#include "crypto.h"

using namespace osx;

Scoped<core::Object> osx::Session::CreateObject
(
    CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
    CK_ULONG                ulCount      /* attributes in template */
)
{
    try {

    }
    CATCH_EXCEPTION
}

Scoped<core::Object> osx::Session::CopyObject
(
    Scoped<core::Object>       object,      /* the object for copying */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
    CK_ULONG             ulCount      /* attributes in template */
)
{
    try {

    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Open
(
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    try {
        core::Session::Open(
            flags,       
            pApplication,
            Notify,      
            phSession    
        );

        digest = Scoped<CryptoDigest>(new CryptoDigest());
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Close()
{
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}