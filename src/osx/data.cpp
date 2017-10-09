#include "data.h"

#include <Security/SecAsn1Types.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Coder.h>

#include "crypto.h"
#include "x509_request_template.h"

using namespace osx;

void osx::Data::Assign
(
 Scoped<Buffer>      data
 )
{
    try {
        
    }
    CATCH_EXCEPTION
}

CK_RV osx::Data::CreateValues
(
 CK_ATTRIBUTE_PTR  pTemplate,
 CK_ULONG          ulCount
 )
{
    try {
        core::Data::CreateValues
        (
         pTemplate,
         ulCount
         );
        
        core::Template tmpl(pTemplate, ulCount);
        Scoped<Buffer> attrValue = tmpl.GetBytes(CKA_VALUE, true);
        
        // Decode ASN1 structure
        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("Error on SecAsn1CoderCreate");
        }
        
        ASN1_X509_REQUEST asn1Request;
        if (SecAsn1Decode(coder, attrValue->data(), attrValue->size(), kX509RequestTemplate, &asn1Request)){
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Cannot decode EC signature");
        }
        
        // Copy SPKI data to buffer
        SecAsn1Item spki = asn1Request.certificationRequestInfo.subjectPublicKeyInfo.subjectPublicKey;
        Scoped<Buffer> spkiBuf(new Buffer(spki.Length << 3));
        memcpy(spkiBuf->data(), spki.Data, spkiBuf->size());
        SecAsn1CoderRelease(coder);
        
        // calculate new CKA_ID, must be SHA-1 digest from SPKI
        Scoped<Buffer> hashBuf(new Buffer(20));
        CryptoDigest digest;
        CK_MECHANISM mech;
        mech.mechanism = CKM_SHA_1;
        mech.pParameter = NULL;
        mech.ulParameterLen = 0;
        digest.Init(&mech);
        CK_ULONG hashSize = 20;
        digest.Once(spkiBuf->data(), spkiBuf->size(), hashBuf->data(), &hashSize);
        
        this->ItemByType(CKA_OBJECT_ID)->To<core::AttributeBytes>()->Set(hashBuf->data(), hashBuf->size());
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Data::CopyValues
(
 Scoped<Object>    object,
 CK_ATTRIBUTE_PTR  pTemplate,
 CK_ULONG          ulCount
 )
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        core::Data::CopyValues
        (
         object,
         pTemplate,
         ulCount
         );
        
        core::Template tmpl(pTemplate, ulCount);
        
        // Use CKA_OBJECT_ID from incoming template
        if (tmpl.HasAttribute(CKA_OBJECT_ID)) {
            Scoped<Buffer> id = tmpl.GetBytes(CKA_OBJECT_ID, true);
            this->ItemByType(CKA_OBJECT_ID)->To<core::AttributeBytes>()->Set(id->data(), id->size());
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Data::Destroy()
{
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}
