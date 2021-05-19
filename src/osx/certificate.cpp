#include "certificate.h"

#include <Security/SecAsn1Coder.h>
#include <CommonCrypto/CommonDigest.h>
#include "x509_template.h"
#include "helper.h"

#include "rsa.h"
#include "ec.h"

using namespace osx;

#define CHAIN_ITEM_TYPE_CERT 1
#define CHAIN_ITEM_TYPE_CRL 2

osx::X509Certificate::X509Certificate()
    : core::X509Certificate(), value(NULL)
{
  Add(core::AttributeBytes::New(CKA_X509_CHAIN, NULL, 0, PVF_2));
}

void osx::X509Certificate::Assign(
    Scoped<SecCertificate> cert /* OSX certificate*/
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value = cert;

    // CKA_LABEL
    {
      CFRef<CFStringRef> cfLabel;
      Scoped<std::string> name = GetName();
      ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->Set(
          (CK_BYTE_PTR)name->c_str(),
          (CK_ULONG)name->size());
    }
    // CKA_SUBJECT
    {
      Scoped<CFData> cfSubjectName = value->GetNormalizedSubjectSequence();
      ItemByType(CKA_SUBJECT)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfSubjectName->GetBytePtr(), cfSubjectName->GetLength());
    }
    // CKA_ISSUER
    {
      Scoped<CFData> cfIssuerName = value->GetNormalizedIssuerSequence();
      ItemByType(CKA_ISSUER)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfIssuerName->GetBytePtr(), cfIssuerName->GetLength());
    }
    // CKA_VALUE
    {
      Scoped<CFData> cfValue = value->GetData();
      ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfValue->GetBytePtr(), cfValue->GetLength());
    }
    // CKA_ID
    Scoped<Buffer> hash = GetPublicKeyHash();
    ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set(hash->data(),
                                                        hash->size());
    // CKA_CHECK_VALUE
    if (hash->size() > 3)
    {
      ItemByType(CKA_CHECK_VALUE)->To<core::AttributeBytes>()->Set(hash->data(), 3);
    }
    // CKA_SERIAL_NUMBER
    {
      osx::SecAsn1Coder coder;

      Scoped<CFData> cfSerialNumber = value->GetSerialNumberData();
      SecAsn1Item serial = SecAsn1Coder::FromCFData(cfSerialNumber.get());

      SecAsn1Item serialEncoded = coder.EncodeItem(&serial, kSecAsn1IntegerTemplate);

      ItemByType(CKA_SERIAL_NUMBER)->To<core::AttributeBytes>()->Set(serialEncoded.Data, serialEncoded.Length);
    }
  }
  CATCH_EXCEPTION
}

Scoped<Buffer> osx::X509Certificate::GetPublicKeyHash()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<core::PublicKey> publicKey = this->GetPublicKey();
    return publicKey->ItemByType(CKA_ID)->ToBytes();
  }
  CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::CreateValues(
    CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
    CK_ULONG ulCount            /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::X509Certificate::CreateValues(
        pTemplate,
        ulCount);
    core::Template tmpl(pTemplate, ulCount);

    Scoped<Buffer> derCert = tmpl.GetBytes(CKA_VALUE, true);

    Scoped<CFData> data = CFData::Create(kCFAllocatorDefault, derCert->data(), derCert->size());
    if (data->IsEmpty())
    {
      THROW_EXCEPTION("Error on CFDataCreate");
    }
    Scoped<SecCertificate> cert = SecCertificate::CreateWithData(NULL, data->Get());

    Assign(cert);

    if (tmpl.GetBool(CKA_TOKEN, false, false))
    {
      AddToMyStorage();
    }
    return CKR_OK;
  }
  CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::CopyValues(
    Scoped<Object> object,      /* the object which must be copied */
    CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
    CK_ULONG ulCount            /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::X509Certificate::CopyValues(object,
                                      pTemplate,
                                      ulCount);
    core::Template tmpl(pTemplate, ulCount);

    X509Certificate *original = dynamic_cast<X509Certificate *>(object.get());

    Scoped<CFData> certData = original->value->GetData();

    Scoped<SecCertificate> cert = SecCertificate::CreateWithData(NULL, certData->Get());
    Assign(cert);

    if (tmpl.GetBool(CKA_TOKEN, false, false))
    {
      AddToMyStorage();
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

void osx::X509Certificate::AddToMyStorage()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value->AddToKeychain(NULL);
  }
  CATCH_EXCEPTION
}

CK_RV osx::X509Certificate::Destroy()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (ItemByType(CKA_TOKEN)->ToBool())
    {
      SecItemDestroy(value->Get());
    }
    return CKR_OK;
  }
  CATCH_EXCEPTION
}

Scoped<core::PublicKey> osx::X509Certificate::GetPublicKey()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<SecKey> secPublicKey = value->GetPublicKey();
    if (secPublicKey->IsEmpty())
    {
      THROW_EXCEPTION("Cannot get public key");
    }

    Scoped<CFDictionary> cfAttributes = secPublicKey->GetAttributes();

    Scoped<core::PublicKey> res;
    Scoped<CFString> cfKeyType = cfAttributes->GetValueOrNull(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->IsEmpty())
    {
      THROW_EXCEPTION("Cannot get type of public key. CFDictionaryGetValue returns empty");
    }
    if (!CFStringCompare(kSecAttrKeyTypeRSA, cfKeyType->Get(), kCFCompareCaseInsensitive))
    {
      Scoped<RsaPublicKey> rsaKey(new RsaPublicKey);
      rsaKey->Assign(secPublicKey);
      res = rsaKey;
    }
    else if (!CFStringCompare(kSecAttrKeyTypeEC, cfKeyType->Get(), kCFCompareCaseInsensitive))
    {
      Scoped<EcPublicKey> ecKey(new EcPublicKey);
      ecKey->Assign(secPublicKey);
      res = ecKey;
    }
    else
    {
      THROW_EXCEPTION("Unsupported key type");
    }

    Scoped<Buffer> certId = ItemByType(CKA_ID)->To<core::AttributeBytes>()->ToValue();

    return res;
  }
  CATCH_EXCEPTION
}

Scoped<core::PrivateKey> osx::X509Certificate::GetPrivateKey()
{
  try
  {
    OSStatus status = 0;
    CFRef<SecIdentityRef> identity = NULL;
    Scoped<core::PrivateKey> res;

    status = SecIdentityCreateWithCertificate(NULL, value->Get(), &identity);
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecIdentityCreateWithCertificate");
    }

    Scoped<SecKey> privateKey = Scoped<SecKey>(new SecKey);
    status = SecIdentityCopyPrivateKey(*identity, privateKey->Ref());
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecIdentityCopyPrivateKey");
    }

    // NOTE: SecKeyCopyAttributes shows dialog if key doesn't have permission for using for current app

    Scoped<core::PublicKey> publicKey = GetPublicKey();
    CK_ULONG ulKeyGenMech = publicKey->ItemByType(CKA_KEY_GEN_MECHANISM)->ToNumber();
    if (ulKeyGenMech == CKM_RSA_PKCS_KEY_PAIR_GEN)
    {
      Scoped<RsaPrivateKey> rsaKey(new RsaPrivateKey);
      rsaKey->Assign(privateKey, publicKey);
      res = rsaKey;
    }
    else if (ulKeyGenMech == CKM_EC_KEY_PAIR_GEN)
    {
      Scoped<EcPrivateKey> ecKey(new EcPrivateKey);
      ecKey->Assign(privateKey, publicKey);
      res = ecKey;
    }
    else
    {
      THROW_EXCEPTION("Unsupported key type");
    }

    return res;
  }
  CATCH_EXCEPTION
}

Scoped<std::string> osx::X509Certificate::GetName()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<std::string> res(new std::string("Unknown name"));
    Scoped<CFString> cfStr = value->GetSubjectSummary();
    if (cfStr->IsEmpty())
    {
      LOGGER_DEBUG("Cannot get common name for certificate");
      return res;
    }

    return cfStr->GetCString();
  }
  CATCH_EXCEPTION
}

bool osx::X509Certificate::HasPrivateKey()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    CFRef<SecIdentityRef> identity = NULL;
    SecIdentityCreateWithCertificate(NULL, value->Get(), &identity);
    if (identity.IsEmpty())
    {
      return false;
    }
    return true;
  }
  CATCH_EXCEPTION
}

Scoped<X509Certificate> osx::X509Certificate::Copy()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<CFData> certData = value->GetData();
    Scoped<SecCertificate> certCopy = SecCertificate::CreateWithData(NULL, certData->Get());
    if (certCopy->IsEmpty())
    {
      THROW_EXCEPTION("Error on SecCertificateCreateWithData");
    }

    Scoped<X509Certificate> res(new X509Certificate);
    res->Assign(certCopy);

    return res;
  }
  CATCH_EXCEPTION
}

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
Scoped<Buffer> GetCertificateChain(
    SecCertificateRef cert // certificate
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    SecTrustRef trust;
    OSStatus status = 0;
    status = SecTrustCreateWithCertificates(cert, NULL, &trust);
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecTrustCreateWithCertificates");
    }
    CFRef<SecTrustRef> scopedTrust = trust;

    status = SecTrustEvaluateWithError(trust, NULL);
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecTrustEvaluate");
    }

    // Get trust resul
    CFRef<CFDictionaryRef> result = SecTrustCopyResult(trust);

    CFArrayRef anchorCertificates = NULL;
    status = SecTrustCopyAnchorCertificates(&anchorCertificates);
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecTrustCopyAnchorCertificates");
    }
    CFRef<CFArrayRef> scopedAnchorCertificates = anchorCertificates;

    std::vector<SecCertificateRef> certs;

    for (CFIndex i = 0; i < SecTrustGetCertificateCount(trust); i++)
    {
      SecCertificateRef chainCert = SecTrustGetCertificateAtIndex(trust, i);
      certs.push_back(chainCert);
    }

    CK_ULONG ulDataLen = 0;
    Scoped<Buffer> res(new Buffer);
    for (int i = 0; i < certs.size(); i++)
    {
      CK_ULONG start = ulDataLen;
      SecCertificateRef pCert = certs.at(i);
      CFRef<CFDataRef> cfCertValue = SecCertificateCopyData(pCert);
      CK_ULONG cfCertValueLen = (CK_ULONG)CFDataGetLength(*cfCertValue);
      CK_BYTE_PTR cfCertValuePtr = (CK_BYTE_PTR)CFDataGetBytePtr(*cfCertValue);

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

CK_RV osx::X509Certificate::GetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    switch (attr->type)
    {
    case CKA_X509_CHAIN:
    {
      auto certs = GetCertificateChain(value->Get());
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
