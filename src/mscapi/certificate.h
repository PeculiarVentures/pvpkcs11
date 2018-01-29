#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
#include "crypt/cert.h"

namespace mscapi {

    class X509Certificate : public core::X509Certificate {
    public:
        X509Certificate(LPWSTR pszProvName = MS_KEY_STORAGE_PROVIDER, DWORD dwProvType = 0, LPWSTR pszScope = L"");

        void Assign(
            Scoped<crypt::Certificate>     cert
        );
        Scoped<crypt::Certificate> Get();

        Scoped<Buffer> GetPublicKeyHash(
            CK_MECHANISM_TYPE       mechType
        );

        CK_RV CreateValues(
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV CopyValues(
            Scoped<Object>    object,     /* the object which must be copied */
            CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
            CK_ULONG          ulCount     /* attributes in template */
        );

        CK_RV Destroy();

        Scoped<core::Object> GetPublicKey();
        Scoped<core::Object> GetPrivateKey();

    protected:
        Scoped<crypt::Certificate> value;
        Scoped<core::Object> publicKey;
        Scoped<core::Object> privateKey;
        std::wstring    wstrProvName;
        std::wstring    wstrScope;
        DWORD           dwProvType;
        
        void AddToMyStorage();
        void AddToSCard();
        CK_RV GetValue
        (
            CK_ATTRIBUTE_PTR  attr
        );
    };


}