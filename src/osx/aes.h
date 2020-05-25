#pragma once

#include "../stdafx.h"

#include "../core/objects/aes_key.h"

#include <Security/Security.h>

namespace osx {

    class AesKey : public core::AesKey {
    public:
        static Scoped<core::SecretKey> Generate(
            CK_MECHANISM_PTR        pMechanism,
            Scoped<core::Template>  tmpl
        );
        
        ~AesKey();
        
        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV Destroy();
        
    };

}
