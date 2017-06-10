#include "certificate.h"

#include <Security/SecAsn1Coder.h>
#include <CommonCrypto/CommonDigest.h>
#include "x509_template.h"

using namespace osx;

void osx::X509Certificate::Assign(
    SecCertificateRef        cert
)
{
    try {
        if (value) {
            
        }
        value = cert;

        // CKA_SUBJECT
        {
            CFDataRef cfSubjectName = SecCertificateCopyNormalizedSubjectSequence(value);
            Scoped<Buffer> subjectName(new Buffer(0));
            subjectName->resize((CK_ULONG)CFDataGetLength(cfSubjectName));
            CFDataGetBytes(cfSubjectName, CFRangeMake(0, subjectName->size()), subjectName->data());
            ItemByType(CKA_SUBJECT)->To<core::AttributeBytes>()->Set(
                subjectName->data(),
                subjectName->size()
            );
            CFRelease(cfSubjectName);
        }
        // CKA_ISSUER
        {
            CFDataRef cfIssuerName = SecCertificateCopyNormalizedIssuerSequence(value);
            Scoped<Buffer> issuerName(new Buffer(0));
            issuerName->resize((CK_ULONG)CFDataGetLength(cfIssuerName));
            CFDataGetBytes(cfIssuerName, CFRangeMake(0, issuerName->size()), issuerName->data());
            ItemByType(CKA_ISSUER)->To<core::AttributeBytes>()->Set(
                issuerName->data(),
                issuerName->size()
            );
            CFRelease(cfIssuerName);
        }
        // CKA_VALUE
        {
            CFDataRef cfValue = SecCertificateCopyData(value);
            Scoped<Buffer> value(new Buffer(0));
            value->resize((CK_ULONG)CFDataGetLength(cfValue));
            CFDataGetBytes(cfValue, CFRangeMake(0, value->size()), value->data());
            ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->Set(
                                                                   value->data(),
                                                                   value->size()
                                                                   );
            CFRelease(cfValue);
        }
        // CKA_ID
        auto hash = GetPublicKeyHash(CKM_SHA_1);
        ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set(
            hash->data(),
            hash->size()
        );
        // CKA_CHECK_VALUE
        if (hash->size() > 3) {
            ItemByType(CKA_CHECK_VALUE)->To<core::AttributeBytes>()->Set(
                hash->data(),
                3
            );
        }
        // CKA_SERIAL_NUMBER
        {
            CFDataRef cfSerialNumber = SecCertificateCopySerialNumber(value, NULL);
            Scoped<Buffer> serialNumber(new Buffer(0));
            serialNumber->resize((CK_ULONG)CFDataGetLength(cfSerialNumber));
            CFDataGetBytes(cfSerialNumber, CFRangeMake(0, serialNumber->size()), serialNumber->data());
            ItemByType(CKA_SERIAL_NUMBER)->To<core::AttributeBytes>()->Set(
                serialNumber->data(),
                serialNumber->size()
            );
            CFRelease(cfSerialNumber);
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> osx::X509Certificate::GetPublicKeyHash(
    CK_MECHANISM_TYPE       mechType
)
{
    try {
        auto der = ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();

        SecAsn1CoderRef coder = NULL;
        SecAsn1CoderCreate(&coder);
        if (!coder) {
            THROW_EXCEPTION("SecAsn1CoderRef is empty");
        }
        
        ASN1_X509 asn1Cert;
        memset(&asn1Cert, 0, sizeof(ASN1_X509));
        OSStatus status = SecAsn1Decode(
                      coder,
                      der->data(), der->size(),
                      kX509Template,
                      &asn1Cert
                      );
        if (status) {
            SecAsn1CoderRelease(coder);
            THROW_EXCEPTION("Cannot decode ASN1 with X509 schema");
        }
        
        Scoped<Buffer> spki(new Buffer);
        spki->resize(asn1Cert.tbsCertificate.derSubjectPublicKeyInfo.Length);
        memcpy(spki->data(), asn1Cert.tbsCertificate.derSubjectPublicKeyInfo.Data, spki->size());
        SecAsn1CoderRelease(coder);
        
        Scoped<Buffer> res(new Buffer);
        switch (mechType) {
            case CKM_SHA_1:
                res->resize(CC_SHA1_DIGEST_LENGTH);
                CC_SHA1(spki->data(), spki->size(), res->data());
                break;
            case CKM_SHA256:
                res->resize(CC_SHA256_DIGEST_LENGTH);
                CC_SHA256(spki->data(), spki->size(), res->data());
                break;
            case CKM_SHA384:
                res->resize(CC_SHA384_DIGEST_LENGTH);
                CC_SHA384(spki->data(), spki->size(), res->data());
                break;
            case CKM_SHA512:
                res->resize(CC_SHA512_DIGEST_LENGTH);
                CC_SHA512(spki->data(), spki->size(), res->data());
                break;
            default:
                THROW_EXCEPTION("Invalid mechanism type must be CKM_SHA_1, CKM_SHA256, CKM_SHA384 or CKM_SHA512");
        }
        
        return res;
    }
    CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::X509Certificate::CreateValues(
            pTemplate,
            ulCount
        );

        core::Template tmpl(pTemplate, ulCount);

//        Scoped<crypt::Certificate> cert(new crypt::Certificate());
//        auto encoded = tmpl.GetBytes(CKA_VALUE, true);
//        cert->Import(encoded->data(), encoded->size());
//        Assign(cert);
//
//        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
//            AddToMyStorage();
//        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::CopyValues(
    Scoped<Object>    object,     /* the object which must be copied */
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::X509Certificate::CopyValues(
            object,
            pTemplate,
            ulCount
        );

        core::Template tmpl(pTemplate, ulCount);

//        X509Certificate* original = dynamic_cast<X509Certificate*>(object.get());
//        
//        auto cert = original->value->Duplicate();
//        Assign(cert);
//
//        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
//            AddToMyStorage();
//        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void osx::X509Certificate::AddToMyStorage()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::Destroy()
{
    try {
        THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
    }
    CATCH_EXCEPTION
}
