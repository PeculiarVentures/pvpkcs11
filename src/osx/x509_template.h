#pragma once

#include <Security/SecAsn1Types.h>
#include <Security/SecAsn1Templates.h>

typedef struct {
    SecAsn1Item algorithm;
    SecAsn1Item parameters;
} ASN1_ALGORITHM_IDENTIFIER;

static const SecAsn1Template kAlgorithmIdentifierTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_ALGORITHM_IDENTIFIER)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_ALGORITHM_IDENTIFIER, algorithm)},
    {SEC_ASN1_ANY_CONTENTS | SEC_ASN1_OPTIONAL, offsetof(ASN1_ALGORITHM_IDENTIFIER, parameters)},
    {0}
};

typedef struct {
    SecAsn1AlgId algorithm;
    SecAsn1Item subjectPublicKey;
} ASN1_SUBJECT_PUBLIC_KEY_INFO;

static const SecAsn1Template kSubjectPublicKeyInfoTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_SUBJECT_PUBLIC_KEY_INFO)},
    {SEC_ASN1_INLINE, offsetof(ASN1_SUBJECT_PUBLIC_KEY_INFO, algorithm), kAlgorithmIdentifierTemplate},
    {SEC_ASN1_BIT_STRING, offsetof(ASN1_SUBJECT_PUBLIC_KEY_INFO, subjectPublicKey)},
    {0}
};

typedef struct {
    SecAsn1Item version;
    SecAsn1Item serialNumber;
    SecAsn1Item signature;
    SecAsn1Item issuer;
    SecAsn1Item validity;
    SecAsn1Item subject;
    ASN1_SUBJECT_PUBLIC_KEY_INFO subjectPublicKeyInfo;
    SecAsn1Item issuerUniqueId;
    SecAsn1Item subjectUniqueId;
    SecAsn1Item extensions;
    SecAsn1Item derSubjectPublicKeyInfo;
} ASN1_TBS_CERTIFICATE;

static const SecAsn1Template kTbsCertificateTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_TBS_CERTIFICATE)},
    {SEC_ASN1_EXPLICIT | SEC_ASN1_CONSTRUCTED | SEC_ASN1_OPTIONAL | SEC_ASN1_CONTEXT_SPECIFIC | 0, offsetof(ASN1_TBS_CERTIFICATE, version), kSecAsn1IntegerTemplate},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, serialNumber)},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, signature)},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, issuer)},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, validity)},
    {SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, subject)},
    {SEC_ASN1_SAVE, offsetof(ASN1_TBS_CERTIFICATE, derSubjectPublicKeyInfo)},
    {SEC_ASN1_INLINE, offsetof(ASN1_TBS_CERTIFICATE, subjectPublicKeyInfo), kSubjectPublicKeyInfoTemplate},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, issuerUniqueId)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, subjectUniqueId)},
    {SEC_ASN1_OPTIONAL | SEC_ASN1_ANY_CONTENTS, offsetof(ASN1_TBS_CERTIFICATE, extensions)},
    {0}
};

typedef struct {
    ASN1_TBS_CERTIFICATE tbsCertificate;
    SecAsn1AlgId signatureAlgorithm;
    SecAsn1Item signatureValue;
} ASN1_X509;


static const SecAsn1Template kX509Template[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_X509)},
    {SEC_ASN1_INLINE, offsetof(ASN1_X509, tbsCertificate), kTbsCertificateTemplate},
    {SEC_ASN1_INLINE, offsetof(ASN1_X509, signatureAlgorithm), kAlgorithmIdentifierTemplate},
    {SEC_ASN1_BIT_STRING, offsetof(ASN1_X509, signatureValue)},
    {0}
};
