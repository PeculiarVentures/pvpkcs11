#include "rsa.h"

#include <Security/Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include "helper.h"

using namespace osx;

typedef struct
{
  SecAsn1Item modulus;
  SecAsn1Item publicExponent;
} ASN1_RSA_PUBLIC_KEY;

const SecAsn1Template kRsaPublicKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PUBLIC_KEY)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, modulus)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PUBLIC_KEY, publicExponent)},
    {0},
};

typedef struct
{
  SecAsn1Item version;
  SecAsn1Item modulus;
  SecAsn1Item publicExponent;
  SecAsn1Item privateExponent;
  SecAsn1Item prime1;
  SecAsn1Item prime2;
  SecAsn1Item exponent1;
  SecAsn1Item exponent2;
  SecAsn1Item coefficient;
} ASN1_RSA_PRIVATE_KEY;

const SecAsn1Template kRsaPrivateKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_RSA_PRIVATE_KEY)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, version)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, modulus)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, publicExponent)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, privateExponent)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime1)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, prime2)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent1)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, exponent2)},
    {SEC_ASN1_INTEGER, offsetof(ASN1_RSA_PRIVATE_KEY, coefficient)},
    {0},
};

Scoped<core::KeyPair> osx::RsaKey::Generate(
    CK_MECHANISM_PTR pMechanism,
    Scoped<core::Template> publicTemplate,
    Scoped<core::Template> privateTemplate)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (pMechanism == NULL)
    {
      THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
    }
    if (pMechanism->mechanism != CKM_RSA_PKCS_KEY_PAIR_GEN)
    {
      THROW_PKCS11_MECHANISM_INVALID();
    }

    Scoped<RsaPrivateKey> privateKey(new RsaPrivateKey());
    privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());

    Scoped<RsaPublicKey> publicKey(new RsaPublicKey());
    publicKey->GenerateValues(publicTemplate->Get(), publicTemplate->Size());

    Scoped<CFMutableDictionary> privateKeyAttr = CFMutableDictionary::Create();
    Scoped<CFMutableDictionary> publicKeyAttr = CFMutableDictionary::Create();
    Scoped<CFMutableDictionary> keyPairAttr = CFMutableDictionary::Create();

    Scoped<SecKey> secPrivateKey = Scoped<SecKey>(new SecKey);
    Scoped<SecKey> secPublicKey = Scoped<SecKey>(new SecKey);

    // private attributes
    keyPairAttr->AddValue(kSecPrivateKeyAttrs, privateKeyAttr->Get());

    // public attributes
    keyPairAttr->AddValue(kSecPublicKeyAttrs, publicKeyAttr->Get());

    // kSecAttrKeyType
    keyPairAttr->AddValue(kSecAttrKeyType, kSecAttrKeyTypeRSA);
    int32_t modulusBits = (int32_t)publicTemplate->GetNumber(CKA_MODULUS_BITS, true);
    Scoped<CFNumber> cfModulusBits = CFNumber::Create(kCFAllocatorDefault,
                                                      kCFNumberSInt32Type,
                                                      &modulusBits);

    // kSecAttrKeySizeInBits
    keyPairAttr->AddValue(kSecAttrKeySizeInBits, cfModulusBits->Get());
    // kSecAttrLabel
    keyPairAttr->AddValue(kSecAttrLabel, kSecAttrLabelModule);
    // kSecAttrAccess
    CFRef<CFStringRef> accessDescription = CFSTR("RSA");
    CFRef<SecAccessRef> access = SecAccessCreateEmptyList(*accessDescription);
    keyPairAttr->AddValue(kSecAttrAccess, *access);

    // Public exponent
    Scoped<Buffer> publicExponent = publicTemplate->GetBytes(CKA_PUBLIC_EXPONENT, true);
    char PUBLIC_EXPONENT_65537[3] = {1, 0, 1};
    if (!(publicExponent->size() == 3 && !memcmp(publicExponent->data(), PUBLIC_EXPONENT_65537, 3)))
    {
      THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Public exponent must be 65537 only");
    }

    SecKey::GeneratePair(keyPairAttr->Get(), secPublicKey->Ref(), secPrivateKey->Ref());

    publicKey->Assign(secPublicKey);
    publicKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
    privateKey->Assign(secPrivateKey);
    privateKey->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
    privateKey->ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->Set(privateTemplate->GetBool(CKA_EXTRACTABLE, false, false));

    return Scoped<core::KeyPair>(new core::KeyPair(privateKey, publicKey));
  }
  CATCH_EXCEPTION
}

// RsaPrivateKey

void osx::RsaPrivateKey::Assign(Scoped<SecKey> key)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value = key;

    CFDictionary cfAttributes = SecKeyCopyAttributesEx(value->Get());
    if (!&cfAttributes)
    {
      THROW_EXCEPTION("Error on SecKeyCopyAttributes");
    }

    // Check key type
    CFStringRef cfKeyType = (CFStringRef)CFDictionaryGetValue(*cfAttributes, kSecAttrKeyType);
    if (cfKeyType == NULL)
    {
      THROW_EXCEPTION("Key item doesn't have kSecAttrKeyType attribute");
    }
    if (CFStringCompare(cfKeyType, kSecAttrKeyTypeRSA, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
    {
      THROW_EXCEPTION("Cannot assign SecKeyRef. It has wrong kSecAttrKeyType");
    }

    Scoped<CFString> cfLabel = cfAttributes.GetValueOrNull(kSecAttrLabel)->To<CFString>();
    if (!cfLabel->IsEmpty())
    {
      ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
          (CK_BYTE_PTR)cfLabel->GetCString()->c_str(),
          cfLabel->GetCString()->size());
    }
    CFDataRef cfAppLabel = (CFDataRef)CFDictionaryGetValue(*cfAttributes, kSecAttrApplicationLabel);
    if (cfAppLabel)
    {
      ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)CFDataGetBytePtr(cfAppLabel),
                                                          CFDataGetLength(cfAppLabel));
    }
    CFBooleanRef cfSign = (CFBooleanRef)CFDictionaryGetValue(*cfAttributes, kSecAttrCanSign);
    if (cfSign == kCFBooleanTrue)
    {
      ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfDecrypt = (CFBooleanRef)CFDictionaryGetValue(*cfAttributes, kSecAttrCanDecrypt);
    if (cfDecrypt == kCFBooleanTrue)
    {
      ItemByType(CKA_DECRYPT)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfUnwrap = (CFBooleanRef)CFDictionaryGetValue(*cfAttributes, kSecAttrCanUnwrap);
    if (cfUnwrap == kCFBooleanTrue)
    {
      ItemByType(CKA_UNWRAP)->To<core::AttributeBool>()->Set(true);
    }
    CFBooleanRef cfExtractable = (CFBooleanRef)CFDictionaryGetValue(*cfAttributes, kSecAttrIsExtractable);
    if (cfExtractable == kCFBooleanTrue)
    {
      ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->Set(true);
    }
  }
  CATCH_EXCEPTION
}

void RsaPrivateKey::Assign(SecAttributeDictionary *attrs)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value = attrs->GetValueRef()->To<SecKey>();

    // Check key type
    Scoped<CFString> cfKeyType = attrs->GetValue(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->Compare(kSecAttrKeyTypeRSA, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
    {
      THROW_EXCEPTION("Cannot assign SecKeyRef. It has wrong kSecAttrKeyType");
    }

    Scoped<CFString> cfLabel = attrs->GetValueOrNull(kSecAttrLabel)->To<CFString>();
    if (!cfLabel->IsEmpty())
    {
      ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
          (CK_BYTE_PTR)cfLabel->GetCString()->c_str(),
          cfLabel->GetCString()->size());
    }

    Scoped<CFData> cfAppLabel = attrs->GetValue(kSecAttrApplicationLabel)->To<CFData>();
    if (!cfAppLabel->IsEmpty())
    {
      ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfAppLabel->GetBytePtr(),
                                                          cfAppLabel->GetLength());
    }

    Scoped<CFBoolean> cfSign = attrs->GetValue(kSecAttrCanSign)->To<CFBoolean>();
    if (cfSign->GetValue())
    {
      ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(true);
    }

    Scoped<CFBoolean> cfDecrypt = attrs->GetValue(kSecAttrCanDecrypt)->To<CFBoolean>();
    if (cfDecrypt->GetValue())
    {
      ItemByType(CKA_DECRYPT)->To<core::AttributeBool>()->Set(true);
    }

    Scoped<CFBoolean> cfUnwrap = attrs->GetValue(kSecAttrCanUnwrap)->To<CFBoolean>();
    if (cfUnwrap->GetValue())
    {
      ItemByType(CKA_UNWRAP)->To<core::AttributeBool>()->Set(true);
    }

    Scoped<CFBoolean> cfDerive = attrs->GetValue(kSecAttrCanDerive)->To<CFBoolean>();
    if (cfDerive->GetValue())
    {
      ItemByType(CKA_DERIVE)->To<core::AttributeBool>()->Set(true);
    }

    // NOTE: Keychain attributes don't keep information about is key extractable or not.
    //       To get that flag you need to call SecKeyCopyAttributes. But it will show
    //       prompt dialog if application doesn't have permission for key using.
    //
    //       For that case mark all private keys like unextractable and public like extractable
    ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->Set(false);

    // Fill public key data
    CK_ULONG modulusLength = 0;
    attrs->GetValue(kSecAttrKeySizeInBits)->To<CFNumber>()->GetValue(kCFNumberSInt32Type, &modulusLength);

    Buffer modulus;
    modulus.resize(modulusLength);
    ItemByType(CKA_MODULUS)->SetValue(modulus.data(), modulusLength);

    CK_BYTE publicExponent[3] = {0x01, 0x00, 0x01};
    ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(publicExponent, 3);
  }
  CATCH_EXCEPTION
}

CK_RV osx::RsaPrivateKey::CopyValues(
    Scoped<core::Object> object, /* the object which must be copied */
    CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
    CK_ULONG ulCount             /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::RsaPrivateKey::CopyValues(object, pTemplate, ulCount);

    core::Template tmpl(pTemplate, ulCount);

    ASN1_RSA_PRIVATE_KEY asn1Key;
    // Modulus
    Scoped<Buffer> modulus = tmpl.GetBytes(CKA_MODULUS, true);
    asn1Key.modulus.Data = modulus->data();
    asn1Key.modulus.Length = modulus->size();
    // Public exponent
    Scoped<Buffer> publicExponent = tmpl.GetBytes(CKA_PUBLIC_EXPONENT, true);
    asn1Key.publicExponent.Data = publicExponent->data();
    asn1Key.publicExponent.Length = publicExponent->size();
    // Private exponent d
    Scoped<Buffer> privateExponent = tmpl.GetBytes(CKA_PRIVATE_EXPONENT, true);
    asn1Key.privateExponent.Data = privateExponent->data();
    asn1Key.privateExponent.Length = privateExponent->size();
    // Prime p
    Scoped<Buffer> prime1 = tmpl.GetBytes(CKA_PRIME_1, true);
    asn1Key.prime1.Data = prime1->data();
    asn1Key.prime1.Length = prime1->size();
    // Prime q
    Scoped<Buffer> prime2 = tmpl.GetBytes(CKA_PRIME_2, true);
    asn1Key.prime2.Data = prime2->data();
    asn1Key.prime2.Length = prime2->size();
    // Private exponent d modulo p -1
    Scoped<Buffer> exponent1 = tmpl.GetBytes(CKA_EXPONENT_1, true);
    asn1Key.exponent1.Data = exponent1->data();
    asn1Key.exponent1.Length = exponent1->size();
    // Private exponent d modulo q -1
    Scoped<Buffer> exponent2 = tmpl.GetBytes(CKA_EXPONENT_2, true);
    asn1Key.exponent2.Data = exponent2->data();
    asn1Key.exponent2.Length = exponent2->size();
    // Private exponent d modulo q -1
    Scoped<Buffer> coefficient = tmpl.GetBytes(CKA_COEFFICIENT, true);
    asn1Key.coefficient.Data = coefficient->data();
    asn1Key.coefficient.Length = coefficient->size();

    SecAsn1Coder coder = SecAsn1Coder();
    SecAsn1Item derKey = coder.EncodeItem(&asn1Key, kRsaPrivateKeyTemplate);

    Scoped<CFMutableDictionary> keyAttrs = CFMutableDictionary::Create();
    keyAttrs
        ->AddValue(kSecAttrKeyType, kSecAttrKeyTypeRSA)
        ->AddValue(kSecAttrKeyClass, kSecAttrKeyClassPrivate);
    Scoped<CFData> derKeyData = CFData::Create(kCFAllocatorDefault, derKey.Data, derKey.Length);
    Scoped<SecKey> key = SecKey::CreateFromData(keyAttrs->Get(), derKeyData->Get());

    Assign(key);

    // Add key to key chain
    OSStatus status = SecItemAdd(keyAttrs->Get(), nullptr);
    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecItemAdd");
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

CK_RV osx::RsaPrivateKey::Destroy()
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

void osx::RsaPrivateKey::FillPublicKeyStruct()
{
  FUNCTION_BEGIN

  Scoped<SecKey> publicKey = value->GetPublicKey();

  // Get public key SEQUENCE
  Scoped<CFData> cfKeyData = publicKey->GetExternalRepresentation();

  // Init ASN1 coder
  Scoped<osx::SecAsn1Coder> coder = osx::SecAsn1Coder::Create();

  ASN1_RSA_PUBLIC_KEY asn1PublicKey;
  coder->DecodeItem(
      cfKeyData->GetBytePtr(),
      cfKeyData->GetLength(),
      kRsaPublicKeyTemplate,
      &asn1PublicKey);

  ItemByType(CKA_MODULUS)->SetValue(asn1PublicKey.modulus.Data, asn1PublicKey.modulus.Length);

  ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(asn1PublicKey.publicExponent.Data, asn1PublicKey.publicExponent.Length);

  FUNCTION_END
}

void osx::RsaPrivateKey::FillPrivateKeyStruct()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    // Get public key SEQUENCE
    CFRef<CFDataRef> cfKeyData = SecKeyCopyExternalRepresentation(value->Get(), NULL);
    if (cfKeyData.IsEmpty())
    {
      THROW_EXCEPTION("Error on SecKeyCopyExternalRepresentation");
    }

    // Init ASN1 coder
    SecAsn1CoderRef coder = NULL;
    SecAsn1CoderCreate(&coder);
    if (!coder)
    {
      THROW_EXCEPTION("Error on SecAsn1CoderCreate");
    }

    ASN1_RSA_PRIVATE_KEY asn1PrivateKey;
    OSStatus status = SecAsn1Decode(coder,
                                    CFDataGetBytePtr(*cfKeyData),
                                    CFDataGetLength(*cfKeyData),
                                    kRsaPrivateKeyTemplate,
                                    &asn1PrivateKey);
    if (status)
    {
      SecAsn1CoderRelease(coder);
      THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
    }

    ItemByType(CKA_PRIVATE_EXPONENT)->SetValue(asn1PrivateKey.privateExponent.Data, asn1PrivateKey.privateExponent.Length);

    ItemByType(CKA_PRIME_1)->SetValue(asn1PrivateKey.prime1.Data, asn1PrivateKey.prime1.Length);

    ItemByType(CKA_PRIME_2)->SetValue(asn1PrivateKey.prime2.Data, asn1PrivateKey.prime2.Length);

    ItemByType(CKA_EXPONENT_1)->SetValue(asn1PrivateKey.exponent1.Data, asn1PrivateKey.exponent1.Length);

    ItemByType(CKA_EXPONENT_2)->SetValue(asn1PrivateKey.exponent2.Data, asn1PrivateKey.exponent2.Length);

    ItemByType(CKA_COEFFICIENT)->SetValue(asn1PrivateKey.coefficient.Data, asn1PrivateKey.coefficient.Length);

    SecAsn1CoderRelease(coder);
  }
  CATCH_EXCEPTION
}

CK_RV osx::RsaPrivateKey::GetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    switch (attr->type)
    {
    case CKA_MODULUS:
    case CKA_PUBLIC_EXPONENT:
    {
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillPublicKeyStruct();
      }
      break;
    }
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_PRIVATE_EXPONENT:
    {
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillPrivateKeyStruct();
      }
      break;
    }
    default:
      return core::RsaPrivateKey::GetValue(attr);
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

// RsaPublicKey

CK_RV osx::RsaPublicKey::CreateValues(
    CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
    CK_ULONG ulCount            /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::RsaPublicKey::CreateValues(pTemplate, ulCount);

    core::Template tmpl(pTemplate, ulCount);

    ASN1_RSA_PUBLIC_KEY asn1Key;
    // Modulus
    Scoped<Buffer> modulus = tmpl.GetBytes(CKA_MODULUS, true);
    asn1Key.modulus.Data = modulus->data();
    asn1Key.modulus.Length = modulus->size();
    // Public exponent
    Scoped<Buffer> publicExponent = tmpl.GetBytes(CKA_PUBLIC_EXPONENT, true);
    asn1Key.publicExponent.Data = publicExponent->data();
    asn1Key.publicExponent.Length = publicExponent->size();

    Scoped<SecAsn1Coder> coder = SecAsn1Coder::Create();
    SecAsn1Item derKey = coder->EncodeItem(&asn1Key, kRsaPublicKeyTemplate);

    Scoped<CFMutableDictionary> keyAttrs = CFMutableDictionary::Create();
    keyAttrs
        ->AddValue(kSecAttrKeyType, kSecAttrKeyTypeRSA)
        ->AddValue(kSecAttrKeyClass, kSecAttrKeyClassPublic);
    Scoped<CFData> derKeyData = CFData::Create(kCFAllocatorDefault, derKey.Data, derKey.Length);
    Scoped<SecKey> key = SecKey::CreateFromData(keyAttrs->Get(), derKeyData->Get());

    Assign(key);

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

CK_RV osx::RsaPublicKey::Destroy()
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

CK_RV osx::RsaPublicKey::CopyValues(
    Scoped<core::Object> object, /* the object which must be copied */
    CK_ATTRIBUTE_PTR pTemplate,  /* specifies attributes */
    CK_ULONG ulCount             /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    THROW_PKCS11_FUNCTION_NOT_SUPPORTED();
  }
  CATCH_EXCEPTION
}

void osx::RsaPublicKey::Assign(Scoped<SecKey> key)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (key == NULL)
    {
      THROW_EXCEPTION("key is NULL");
    }
    value = key;

    Scoped<CFDictionary> cfAttributes = value->GetAttributes();

    // Check key type
    Scoped<CFString> cfKeyType = cfAttributes->GetValueOrNull(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->IsEmpty())
    {
      THROW_EXCEPTION("Key item doesn't have kSecAttrKeyType attribute");
    }
    if (cfKeyType->Compare(kSecAttrKeyTypeRSA, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
    {
      THROW_EXCEPTION("Cannot assign SecKeyRef. It has wrong kSecAttrKeyType");
    }

    Scoped<CFString> cfLabel = cfAttributes->GetValueOrNull(kSecAttrLabel)->To<CFString>();
    if (!cfLabel->IsEmpty())
    {
      ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
          (CK_BYTE_PTR)cfLabel->GetCString()->c_str(),
          cfLabel->GetCString()->size());
    }

    Scoped<CFData> cfAppLabel = cfAttributes->GetValueOrNull(kSecAttrApplicationLabel)->To<CFData>();
    if (cfAppLabel)
    {
      ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfAppLabel->GetBytePtr(),
                                                          cfAppLabel->GetLength());
    }
    Scoped<CFBoolean> cfVerify = cfAttributes->GetValue(kSecAttrCanVerify)->To<CFBoolean>();
    if (cfVerify->GetValue())
    {
      ItemByType(CKA_VERIFY)->To<core::AttributeBool>()->Set(true);
    }
    Scoped<CFBoolean> cfEncrypt = cfAttributes->GetValue(kSecAttrCanEncrypt)->To<CFBoolean>();
    if (cfEncrypt->GetValue())
    {
      ItemByType(CKA_ENCRYPT)->To<core::AttributeBool>()->Set(true);
    }
    Scoped<CFBoolean> cfWrap = cfAttributes->GetValue(kSecAttrCanWrap)->To<CFBoolean>();
    if (cfWrap->GetValue())
    {
      ItemByType(CKA_WRAP)->To<core::AttributeBool>()->Set(true);
    }

    // FillKeyStruct();
  }
  CATCH_EXCEPTION
}

void osx::RsaPublicKey::FillKeyStruct()
{
  FUNCTION_BEGIN

  Scoped<CFDictionary> cfAttributes = value->GetAttributes();

  // Get public key SEQUENCE
  Scoped<CFData> cfKeyData = NULL;

  try
  {
    cfKeyData = value->GetExternalRepresentation();
  }
  catch (Scoped<core::Exception> e)
  {
    // LOGGER_WARN("Cannot export RSA public key. %s", e->message.c_str());
  }

  if (cfKeyData.get() != nullptr)
  {
    puts("!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!");
    // Init ASN1 coder
    Scoped<SecAsn1Coder> coder = SecAsn1Coder::Create();

    ASN1_RSA_PUBLIC_KEY asn1PublicKey;
    coder->DecodeItem(
        cfKeyData->GetBytePtr(),
        cfKeyData->GetLength(),
        kRsaPublicKeyTemplate,
        &asn1PublicKey);

    ItemByType(CKA_MODULUS_BITS)->To<core::AttributeNumber>()->Set(asn1PublicKey.modulus.Length * 8);

    ItemByType(CKA_MODULUS)->SetValue(asn1PublicKey.modulus.Data, asn1PublicKey.modulus.Length);
    ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(asn1PublicKey.publicExponent.Data, asn1PublicKey.publicExponent.Length);
  }
  else
  {
    Scoped<CFDictionary> attrs = value->GetAttributes();
    CK_ULONG modulusLength = 0;
    attrs->GetValue(kSecAttrKeySizeInBits)->To<CFNumber>()->GetValue(kCFNumberSInt32Type, &modulusLength);

    ItemByType(CKA_MODULUS_BITS)->To<core::AttributeNumber>()->Set(modulusLength);

    CK_BYTE modulus[0] = {};
    ItemByType(CKA_MODULUS)->SetValue(modulus, 0);

    CK_BYTE publicExponent[3] = {0x01, 0x00, 0x01};
    ItemByType(CKA_PUBLIC_EXPONENT)->SetValue(publicExponent, 3);
  }

  FUNCTION_END
}

CK_RV osx::RsaPublicKey::GetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    switch (attr->type)
    {
    case CKA_MODULUS:
    case CKA_MODULUS_BITS:
    case CKA_PUBLIC_EXPONENT:
    {
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillKeyStruct();
      }
      break;
    }
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}
