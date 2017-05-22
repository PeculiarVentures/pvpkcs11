#include "../stdafx.h"
#include "../core/objects/data.h"

#define CERT_PV_REQUEST    (CERT_FIRST_USER_PROP_ID + 1)
#define CERT_PV_ID         (CERT_FIRST_USER_PROP_ID + 2)

namespace mscapi {

    class X509CertificateRequest : public core::Data {
    public:
        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,
            CK_ULONG          ulCount
        );
        CK_RV CopyValues(
            Scoped<Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );
    protected:
        Scoped<CERT_CONTEXT>    context;
    };

}