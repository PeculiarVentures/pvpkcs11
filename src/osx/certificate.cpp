#include "certificate.h"

#include <Security/SecAsn1Coder.h>
#include <CommonCrypto/CommonDigest.h>
#include "x509_template.h"
#include "helper.h"

#include "rsa.h"
#include "ec.h"

using namespace osx;

#define CHAIN_ITEM_TYPE_CERT                1
#define CHAIN_ITEM_TYPE_CRL                 2

osx::X509Certificate::X509Certificate()
: core::X509Certificate(), value(NULL)
{
    Add(core::AttributeBytes::New(CKA_X509_CHAIN, NULL, 0, PVF_2));
}

SecCertificateRef osx::X509Certificate::Get()
{
    return this->value.Get();
}

void osx::X509Certificate::Assign(
    SecCertificateRef        cert
)
{
    try {
        value = cert;

        // CKA_SUBJECT
        {
            CFRef<CFDataRef> cfSubjectName = SecCertificateCopyNormalizedSubjectSequence(&value);
            Scoped<Buffer> subjectName(new Buffer(0));
            subjectName->resize((CK_ULONG)CFDataGetLength(&cfSubjectName));
            CFDataGetBytes(&cfSubjectName, CFRangeMake(0, subjectName->size()), subjectName->data());
            ItemByType(CKA_SUBJECT)->To<core::AttributeBytes>()->Set(
                subjectName->data(),
                subjectName->size()
            );
        }
        // CKA_ISSUER
        {
            CFRef<CFDataRef> cfIssuerName = SecCertificateCopyNormalizedIssuerSequence(&value);
            Scoped<Buffer> issuerName(new Buffer(0));
            issuerName->resize((CK_ULONG)CFDataGetLength(&cfIssuerName));
            CFDataGetBytes(&cfIssuerName, CFRangeMake(0, issuerName->size()), issuerName->data());
            ItemByType(CKA_ISSUER)->To<core::AttributeBytes>()->Set(
                issuerName->data(),
                issuerName->size()
            );
        }
        // CKA_VALUE
        {
            CFRef<CFDataRef> cfValue = SecCertificateCopyData(&value);
            Scoped<Buffer> value(new Buffer(0));
            value->resize((CK_ULONG)CFDataGetLength(&cfValue));
            CFDataGetBytes(&cfValue, CFRangeMake(0, value->size()), value->data());
            ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->Set(
                                                                   value->data(),
                                                                   value->size()
                                                                   );
        }
        // CKA_ID
        Scoped<Buffer> hash = GetPublicKeyHash(CKM_SHA_1);
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
            CFRef<CFDataRef> cfSerialNumber = SecCertificateCopySerialNumber(&value, NULL);
            Scoped<Buffer> serialNumber(new Buffer(0));
            serialNumber->resize((CK_ULONG)CFDataGetLength(&cfSerialNumber));
            CFDataGetBytes(&cfSerialNumber, CFRangeMake(0, serialNumber->size()), serialNumber->data());
            ItemByType(CKA_SERIAL_NUMBER)->To<core::AttributeBytes>()->Set(
                serialNumber->data(),
                serialNumber->size()
            );
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> osx::X509Certificate::GetPublicKeyHash(
    CK_MECHANISM_TYPE       mechType
)
{
    try {
        Scoped<Buffer> der = ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->ToValue();

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
            THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
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
        
        Scoped<Buffer> derCert = tmpl.GetBytes(CKA_VALUE, true);
        
        CFRef<CFDataRef> data = CFDataCreate(NULL, derCert->data(), derCert->size());
        if (data.IsEmpty()) {
            THROW_EXCEPTION("Error on CFDataCreate");
        }
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, &data);
        if (!cert) {
            THROW_EXCEPTION("Cannot create Certificate from CKA_VALUE");
        }
        
        Assign(cert);
        
        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            AddToMyStorage();
        }
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

        X509Certificate* original = dynamic_cast<X509Certificate*>(object.get());
        
        CFRef<CFDataRef> certData = SecCertificateCopyData(&original->value);
        
        SecCertificateRef cert = SecCertificateCreateWithData(NULL, &certData);
        Assign(cert);

        if (tmpl.GetBool(CKA_TOKEN, false, false)) {
            AddToMyStorage();
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void osx::X509Certificate::AddToMyStorage()
{
    try {
        SecCertificateAddToKeychain(&value, NULL);
    }
    CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::Destroy()
{
    try {
        OSStatus status;
        CFRef<CFMutableDictionaryRef> matchAttr = CFDictionaryCreateMutable(kCFAllocatorDefault,
                                                                            0,
                                                                            &kCFTypeDictionaryKeyCallBacks,
                                                                            &kCFTypeDictionaryValueCallBacks);
        SecCertificateRef certArray[] = { value.Get() };
        CFDictionaryAddValue(&matchAttr, kSecClass, kSecClassCertificate);
        CFRef<CFArrayRef> itemList = CFArrayCreate(NULL, (const void**)certArray , 1, &kCFTypeArrayCallBacks);
        CFDictionaryAddValue(&matchAttr, kSecMatchItemList, &itemList);
        
        if ((status = SecItemDelete(&matchAttr))) {
            THROW_OSX_EXCEPTION(status, "SecItemDelete");
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

Scoped<core::PublicKey> osx::X509Certificate::GetPublicKey()
{
    try {
        SecKeyRef secPublicKey = NULL;
        SecCertificateCopyPublicKey(&value, &secPublicKey);
        if (!secPublicKey) {
            THROW_EXCEPTION("Cannot get public key");
        }

        CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributes(secPublicKey);
        if (!&cfAttributes) {
            CFRelease(secPublicKey);
            THROW_EXCEPTION("Error on SecKeyCopyAttributes");
        }
        
        Scoped<core::PublicKey> res;
        CFStringRef cfKeyType = static_cast<CFStringRef>(CFDictionaryGetValue(&cfAttributes, kSecAttrKeyType));
        if (!CFStringCompare(kSecAttrKeyTypeRSA, cfKeyType, kCFCompareCaseInsensitive)) {
            Scoped<RsaPublicKey> rsaKey(new RsaPublicKey);
            rsaKey->Assign(secPublicKey);
            res = rsaKey;
        } else if (!CFStringCompare(kSecAttrKeyTypeEC, cfKeyType, kCFCompareCaseInsensitive)) {
            Scoped<EcPublicKey> ecKey(new EcPublicKey);
            ecKey->Assign(secPublicKey);
            res = ecKey;
        } else {
            THROW_EXCEPTION("Unsupported key type");
        }
        
        Scoped<Buffer> certId = ItemByType(CKA_ID)->To<core::AttributeBytes>()->ToValue();
        res->ItemByType(CKA_ID)->SetValue(certId->data(), certId->size());
        
        return res;
    }
    CATCH_EXCEPTION
}

Scoped<core::PrivateKey> osx::X509Certificate::GetPrivateKey()
{
    try {
        SecIdentityRef identity = NULL;
        SecIdentityCreateWithCertificate(NULL, &value, &identity);
        if (!identity) {
            THROW_EXCEPTION("Error on SecIdentityCreateWithCertificate");
        }
        CFRef<SecIdentityRef> scopedIdentity = identity;

        SecKeyRef privateKey = NULL;
        SecIdentityCopyPrivateKey(identity, &privateKey);
        if (!privateKey) {
            THROW_EXCEPTION("Cannot get private key");
        }
        
        CFRef<CFDictionaryRef> attributes = SecKeyCopyAttributes(privateKey);
        
        CFStringRef cfKeyType = static_cast<CFStringRef>(CFDictionaryGetValue(&attributes, kSecAttrKeyType));
        Scoped<core::PrivateKey> res;
        if (!CFStringCompare(kSecAttrKeyTypeRSA, cfKeyType, kCFCompareCaseInsensitive)) {
            Scoped<RsaPrivateKey> rsaKey(new RsaPrivateKey);
            rsaKey->Assign(privateKey);
            res = rsaKey;
        } else if (!CFStringCompare(kSecAttrKeyTypeEC, cfKeyType, kCFCompareCaseInsensitive)) {
            Scoped<EcPrivateKey> ecKey(new EcPrivateKey);
            ecKey->Assign(privateKey);
            res = ecKey;
        } else {
            CFRelease(privateKey);
            THROW_EXCEPTION("Unsupported key type");
        }
        
        Scoped<Buffer> certId = ItemByType(CKA_ID)->To<core::AttributeBytes>()->ToValue();
        res->ItemByType(CKA_ID)->SetValue(certId->data(), certId->size());
        
        return res;
    }
    CATCH_EXCEPTION
}

bool osx::X509Certificate::HasPrivateKey()
{
    try {
        SecIdentityRef identity = NULL;
        SecIdentityCreateWithCertificate(NULL, &value, &identity);
        if (!identity) {
            return false;
        }
        CFRelease(identity);
        return true;
    }
    CATCH_EXCEPTION
}

static CFStringRef kSecTrustResultDetails = (CFSTR("TrustResultDetails"));
static CFStringRef kSecTrustResultDetailsTitle = (CFSTR("title"));

/*
 Returns DER collection of certificates
 
 CK_ULONG itemType
 CK_ULONG itemSize
 CK_BYTE itemValue[certSize]
 ...
 CK_ULONG itemType
 CK_ULONG itemSize
 CK_BYTE itemValue[certSize]
 */
Scoped<Buffer> GetCertificateChain
(
 SecCertificateRef     cert       // certificate
)
{
    try {
        SecTrustRef trust;
        OSStatus status = 0;
        status = SecTrustCreateWithCertificates(cert, NULL, &trust);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecTrustCreateWithCertificates");
        }
        CFRef<SecTrustRef> scopedTrust = trust;
        
        status = SecTrustEvaluate(trust, NULL);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecTrustEvaluate");
        }
        
        // Get trust resul
        CFRef<CFDictionaryRef> result = SecTrustCopyResult(trust);
//        CFShow(&result);
        
        CFArrayRef anchorCertificates = NULL;
        status = SecTrustCopyAnchorCertificates(&anchorCertificates);
        if (status) {
            THROW_OSX_EXCEPTION(status, "SecTrustCopyAnchorCertificates");
        }
        CFRef<CFArrayRef> scopedAnchorCertificates = anchorCertificates;
        
        std::vector<SecCertificateRef> certs;
        
        for (CFIndex i = 0; i < SecTrustGetCertificateCount(trust); i++) {
            SecCertificateRef chainCert = SecTrustGetCertificateAtIndex(trust, i);
            certs.push_back(chainCert);
        }
        
        CK_ULONG ulDataLen = 0;
        Scoped<Buffer> res(new Buffer);
        for (int i = 0; i < certs.size(); i++) {
            CK_ULONG start = ulDataLen;
            SecCertificateRef pCert = certs.at(i);
            CFRef<CFDataRef> cfCertValue = SecCertificateCopyData(pCert);
            CK_ULONG cfCertValueLen = (CK_ULONG)CFDataGetLength(&cfCertValue);
            CK_BYTE_PTR cfCertValuePtr = (CK_BYTE_PTR)CFDataGetBytePtr(&cfCertValue);

            // itemType
            res->resize(++ulDataLen);
            auto itemType = CHAIN_ITEM_TYPE_CERT;
            // itemSize
            ulDataLen += sizeof(CK_ULONG);
            // itemValue
            ulDataLen += cfCertValueLen;
            res->resize(ulDataLen);
            CK_BYTE_PTR pCertData = res->data() + start;
            memcpy(pCertData, &itemType, 1);
            memcpy(pCertData + 1, &cfCertValueLen, sizeof(CK_ULONG));
            memcpy(pCertData + 1 + sizeof(CK_ULONG), cfCertValuePtr, cfCertValueLen);
        }
        
        return res;
    }
    CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::GetValue
(
 CK_ATTRIBUTE_PTR  attr
 )
{
    try {
        switch (attr->type) {
            case CKA_X509_CHAIN: {
                auto certs = GetCertificateChain(this->Get());
                ItemByType(CKA_X509_CHAIN)->SetValue(certs->data(), certs->size());
                break;
            }
            default:
                core::Object::GetValue(attr);
        }
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}
