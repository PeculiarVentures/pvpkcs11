#pragma once

#include <Security/SecAsn1Types.h>
#include <Security/SecAsn1Templates.h>

#include "./x509_template.h"

typedef struct
{
    SecAsn1Item version;
    SecAsn1Item subject;
    ASN1_SUBJECT_PUBLIC_KEY_INFO subjectPublicKeyInfo;
    SecAsn1Item attributes;
} ASN1_CERTIFICATION_REQUEST_INFO;

static const SecAsn1Template kCertificateRequestInfoTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_CERTIFICATION_REQUEST_INFO)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_INTEGER, offsetof(ASN1_CERTIFICATION_REQUEST_INFO, version), kSecAsn1IntegerTemplate},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_CERTIFICATION_REQUEST_INFO, subject)},
    {SEC_ASN1_INLINE, offsetof(ASN1_TBS_CERTIFICATE, subjectPublicKeyInfo), kSubjectPublicKeyInfoTemplate},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_CERTIFICATION_REQUEST_INFO, attributes)},
    {0}};

typedef struct
{
    ASN1_TBS_CERTIFICATE certificationRequestInfo;
    SecAsn1AlgId signatureAlgorithm;
    SecAsn1Item signature;
} ASN1_X509_REQUEST;

static const SecAsn1Template kX509RequestTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_X509)},
    {SEC_ASN1_INLINE, offsetof(ASN1_X509, tbsCertificate), kCertificateRequestInfoTemplate},
    {SEC_ASN1_INLINE, offsetof(ASN1_X509, signatureAlgorithm), kAlgorithmIdentifierTemplate},
    {SEC_ASN1_BIT_STRING, offsetof(ASN1_X509, signatureValue)},
    {0}
};
