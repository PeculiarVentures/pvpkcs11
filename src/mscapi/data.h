#include "../stdafx.h"
#include "../core/objects/data.h"
#include "crypt/cert.h"

#define CERT_PV_REQUEST    0x00008001
#define CERT_PV_ID         0x00008002

namespace mscapi {

    class X509CertificateRequest : public core::Data {
    public:
        void Assign(
            Scoped<crypt::Certificate>      cert
        );
        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,
            CK_ULONG          ulCount
        );
        CK_RV CopyValues(
            Scoped<Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );
        CK_RV Destroy();
    protected:
        Scoped<crypt::Certificate>  cert;
    };

}