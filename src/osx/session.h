#pragma once

#include "../core/session.h"

namespace osx {

    class Session: public core::Session {
    public:
        Session() {}

        CK_RV Open
		(
			CK_FLAGS              flags,         /* from CK_SESSION_INFO */
			CK_VOID_PTR           pApplication,  /* passed to callback */
			CK_NOTIFY             Notify,        /* callback function */
			CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
		);

		CK_RV Close();

        Scoped<core::Object> CreateObject
        (
            CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
            CK_ULONG                ulCount      /* attributes in template */
        );

        Scoped<core::Object> CopyObject
        (
            Scoped<core::Object>       object,      /* the object for copying */
            CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
            CK_ULONG             ulCount      /* attributes in template */
        );

        CK_RV GenerateRandom(
            CK_BYTE_PTR       pPart,     /* data to be digested */
            CK_ULONG          ulPartLen  /* bytes of data to be digested */
        );
    };

}