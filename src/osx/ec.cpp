#include "ec.h"

#include <Security/Security.h>
#include <Security/SecAsn1Coder.h>
#include <Security/SecAsn1Templates.h>
#include <Security/SecAsn1Types.h>
#include "aes.h"
#include "helper.h"

using namespace osx;

typedef struct
{
  SecAsn1Item algorithm;
  SecAsn1Item namedCurve;
} ASN1_EC_ALGORITHM_IDENTIFIER;

const SecAsn1Template kEcAlgorithmIdTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_ALGORITHM_IDENTIFIER)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, algorithm)},
    {SEC_ASN1_OBJECT_ID, offsetof(ASN1_EC_ALGORITHM_IDENTIFIER, namedCurve)},
    {0}};

typedef struct
{
  ASN1_EC_ALGORITHM_IDENTIFIER algorithm;
  SecAsn1Item publicKey;
} ASN1_EC_PUBLIC_KEY;

const SecAsn1Template kEcPublicKeyTemplate[] = {
    {SEC_ASN1_SEQUENCE, 0, NULL, sizeof(ASN1_EC_PUBLIC_KEY)},
    {SEC_ASN1_INLINE, offsetof(ASN1_EC_PUBLIC_KEY, algorithm), kEcAlgorithmIdTemplate},
    {SEC_ASN1_BIT_STRING, offsetof(ASN1_EC_PUBLIC_KEY, publicKey)},
    {0}};

Scoped<CFData> GetKeyDataFromOctetString(CFDataRef octetString)
{
  LOGGER_FUNCTION_BEGIN;

  CFData cfOctetString(octetString);
  cfOctetString.Unref();

  Scoped<osx::SecAsn1Coder> coder = osx::SecAsn1Coder::Create();
  SecAsn1Item keyData;

  coder->DecodeItem(cfOctetString.GetBytePtr(), cfOctetString.GetLength(), kSecAsn1OctetStringTemplate, &keyData);

  return CFData::Create(kCFAllocatorDefault, keyData.Data, keyData.Length);
}

CFDataRef CopyKeyDataToOctetString(UInt8 *data, CFIndex dataLen)
{
  SecAsn1CoderRef coder;
  SecAsn1CoderCreate(&coder);

  SecAsn1Item octetString;
  octetString.Data = data;
  octetString.Length = dataLen;
  SecAsn1Item keyData;
  OSStatus status = SecAsn1EncodeItem(coder, &octetString, kSecAsn1OctetStringTemplate, &keyData);
  if (status)
  {
    SecAsn1CoderRelease(coder);
    return NULL;
  }

  CFDataRef res = CFDataCreate(kCFAllocatorDefault, keyData.Data, keyData.Length);

  SecAsn1CoderRelease(coder);

  return res;
}

CK_ULONG GetKeySize(const UInt8 *data, CFIndex dataLen)
{
  if (data && dataLen && data[0] == 4)
  {
    switch ((dataLen - 1) >> 1)
    {
    case 32:
      return 256;
    case 48:
      return 384;
    case 66:
      return 521;
    }
  }
  return 0;
}

Scoped<CFData> SetKeyDataToPublicKey(const UInt8 *data, CFIndex dataLen)
{
  LOGGER_FUNCTION_BEGIN;

  Scoped<osx::SecAsn1Coder> coder = osx::SecAsn1Coder::Create();

  ASN1_EC_PUBLIC_KEY publicKey;
  publicKey.algorithm.algorithm.Data = (unsigned char *)"\x2A\x86\x48\xCE\x3D\x02\x01"; // ecPublicKey(ANSI X9.62 public key type)
  publicKey.algorithm.algorithm.Length = 7;

  CK_ULONG keySizeInBits = GetKeySize(data, dataLen);
  if (!keySizeInBits)
  {
    return NULL;
  }
  switch (keySizeInBits)
  {
  case 256:
    publicKey.algorithm.namedCurve.Data = (unsigned char *)"\x2A\x86\x48\xCE\x3D\x03\x01\x07";
    publicKey.algorithm.namedCurve.Length = 8;
    break;
  case 384:
    publicKey.algorithm.namedCurve.Data = (unsigned char *)"\x2B\x81\x04\x00\x22";
    publicKey.algorithm.namedCurve.Length = 5;
    break;
  case 521:
    publicKey.algorithm.namedCurve.Data = (unsigned char *)"\x2B\x81\x04\x00\x23";
    publicKey.algorithm.namedCurve.Length = 5;
    break;
  default:
    return NULL;
  }

  publicKey.publicKey.Data = (uint8_t *)data;
  publicKey.publicKey.Length = dataLen << 3;

  SecAsn1Item keyData = coder->EncodeItem(&publicKey, kEcPublicKeyTemplate);

  return CFData::Create(kCFAllocatorDefault, keyData.Data, keyData.Length);
}

Scoped<core::KeyPair> osx::EcKey::Generate(
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
    if (pMechanism->mechanism != CKM_EC_KEY_PAIR_GEN)
    {
      THROW_PKCS11_MECHANISM_INVALID();
    }

    Scoped<EcPrivateKey> privateKey(new EcPrivateKey());
    privateKey->GenerateValues(privateTemplate->Get(), privateTemplate->Size());

    Scoped<EcPublicKey> publicKey(new EcPublicKey());
    publicKey->GenerateValues(publicTemplate->Get(), publicTemplate->Size());

    Scoped<CFMutableDictionary> privateKeyAttr = CFMutableDictionary::Create();
    Scoped<CFMutableDictionary> publicKeyAttr = CFMutableDictionary::Create();
    Scoped<CFMutableDictionary> keyPairAttr = CFMutableDictionary::Create();

    Scoped<SecKey> secPrivateKey = Scoped<SecKey>(new SecKey);
    Scoped<SecKey> secPublicKey = Scoped<SecKey>(new SecKey);

    Scoped<Buffer> params = publicTemplate->GetBytes(CKA_EC_PARAMS, true, "");
    unsigned int keySizeInBits = 0;

#define POINT_COMPARE(curve) memcmp(core::EC_##curve##_BLOB, params->data(), sizeof(core::EC_##curve##_BLOB) - 1) == 0

    if (POINT_COMPARE(P256))
    {
      keySizeInBits = 256;
    }
    else if (POINT_COMPARE(P384))
    {
      keySizeInBits = 384;
    }
    else if (POINT_COMPARE(P521))
    {
      keySizeInBits = 521;
    }
    else
    {
      THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Wrong POINT for EC key");
    }

#undef POINT_COMPARE

    keyPairAttr->AddValue(kSecAttrKeyType, kSecAttrKeyTypeEC);
    Scoped<CFNumber> cfKeySizeInBits = CFNumber::Create(kCFAllocatorDefault,
                                                        kCFNumberSInt32Type,
                                                        &keySizeInBits);
    keyPairAttr->AddValue(kSecAttrKeySizeInBits, cfKeySizeInBits->Get());

    keyPairAttr->AddValue(kSecAttrLabel, kSecAttrLabelModule);
    keyPairAttr->AddValue(kSecPrivateKeyAttrs, privateKeyAttr->Get());
    keyPairAttr->AddValue(kSecPublicKeyAttrs, publicKeyAttr->Get());
    // kSecAttrAccess
    CFRef<CFStringRef> appDescription = CFSTR("ECC");
    CFRef<SecAccessRef> access = SecAccessCreateEmptyList(*appDescription);
    keyPairAttr->AddValue(kSecAttrAccess, *access);

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

Scoped<core::Object> EcKey::DeriveKey(
    CK_MECHANISM_PTR pMechanism,
    Scoped<core::Object> baseKey,
    Scoped<core::Template> tmpl)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    EcPrivateKey *ecPrivateKey = dynamic_cast<EcPrivateKey *>(baseKey.get());
    if (!ecPrivateKey)
    {
      THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "baseKey is not EC key");
    }

    if (pMechanism == NULL_PTR)
    {
      THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
    }
    if (pMechanism->mechanism != CKM_ECDH1_DERIVE)
    {
      THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "pMechanism->mechanism is not CKM_ECDH1_DERIVE");
    }
    if (pMechanism->pParameter == NULL_PTR)
    {
      THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
    }
    CK_ECDH1_DERIVE_PARAMS_PTR params = static_cast<CK_ECDH1_DERIVE_PARAMS_PTR>(pMechanism->pParameter);
    if (!params)
    {
      THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is not CK_ECDH1_DERIVE_PARAMS");
    }

    Key *privateKey = dynamic_cast<Key *>(baseKey.get());
    if (!privateKey)
    {
      THROW_EXCEPTION("Cannot get SecKeyRef from Object");
    }

    // Create public key from public data
    Scoped<CFData> publicData = CFData::Create(kCFAllocatorDefault, params->pPublicData, params->ulPublicDataLen);
    Scoped<CFData> keyData = GetKeyDataFromOctetString(publicData->Get());

    Scoped<CFData> spki = SetKeyDataToPublicKey(keyData->GetBytePtr(), keyData->GetLength());
    if (spki->IsEmpty())
    {
      THROW_EXCEPTION("Error on SetKeyDataToPublicKey");
    }

    Scoped<CFMutableDictionary> keyAttr = CFMutableDictionary::Create();
    keyAttr
        ->SetValue(kSecAttrKeyType, kSecAttrKeyTypeEC)
        ->SetValue(kSecAttrKeyClass, kSecAttrKeyClassPublic);

    CFRef<CFErrorRef> error = NULL;
    Scoped<SecKey> publicKey = SecKey::CreateFromData(keyAttr->Get(), spki->Get());
    Scoped<CFDictionary> attrs = publicKey->GetAttributes();
    Scoped<CFData> blob = publicKey->GetExternalRepresentation();

    Scoped<CFMutableDictionary> parameters = CFMutableDictionary::Create();
    Scoped<CFData> derivedData = privateKey->Get()->GetKeyExchangeResult(
        kSecKeyAlgorithmECDHKeyExchangeStandard,
        publicKey->Get(),
        parameters->Get());

    puts("Derived");
    const UInt8 *data = derivedData->GetBytePtr();
    for (int i = 0; i < derivedData->GetLength(); i++)
    {
      printf("%02X", data[i]);
    }
    puts("");

    THROW_EXCEPTION("Not finished");
  }
  CATCH_EXCEPTION
}

// EcPrivateKey

void osx::EcPrivateKey::Assign(Scoped<SecKey> key)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value = key;

    Scoped<CFDictionary> cfAttributes = value->GetAttributes();

    // Check key type
    Scoped<CFString> cfKeyType = cfAttributes->GetValue(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->Compare(kSecAttrKeyTypeEC, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
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

    Scoped<CFData> cfAppLabel = cfAttributes->GetValue(kSecAttrApplicationLabel)->To<CFData>();
    if (!cfAppLabel->IsEmpty())
    {
      ItemByType(CKA_ID)->To<core::AttributeBytes>()->Set((CK_BYTE_PTR)cfAppLabel->GetBytePtr(),
                                                          cfAppLabel->GetLength());
    }
    Scoped<CFBoolean> cfSign = cfAttributes->GetValue(kSecAttrCanSign)->To<CFBoolean>();
    if (cfSign->GetValue())
    {
      ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(true);
    }
    Scoped<CFBoolean> cfDecrypt = cfAttributes->GetValue(kSecAttrCanDecrypt)->To<CFBoolean>();
    if (cfDecrypt->GetValue())
    {
      ItemByType(CKA_DECRYPT)->To<core::AttributeBool>()->Set(true);
    }
    Scoped<CFBoolean> cfUnwrap = cfAttributes->GetValue(kSecAttrCanUnwrap)->To<CFBoolean>();
    if (cfUnwrap->GetValue())
    {
      ItemByType(CKA_UNWRAP)->To<core::AttributeBool>()->Set(true);
    }
    Scoped<CFBoolean> cfExtractable = cfAttributes->GetValue(kSecAttrIsExtractable)->To<CFBoolean>();
    if (cfExtractable->GetValue())
    {
      ItemByType(CKA_EXTRACTABLE)->To<core::AttributeBool>()->Set(true);
    }
  }
  CATCH_EXCEPTION
}

void osx::EcPrivateKey::Assign(Scoped<SecKey> key, Scoped<core::PublicKey> publicKey)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<Buffer> tmpAttr;
    core::PublicKey *pPubKey = publicKey.get();

    if (!pPubKey)
    {
      THROW_PARAM_REQUIRED_EXCEPTION("publicKey");
    }

    // Check public, it must be EC
    if (publicKey->ItemByType(CKA_KEY_GEN_MECHANISM)->ToNumber() != CKM_EC_KEY_PAIR_GEN)
    {
      THROW_EXCEPTION("Cannot assing key. Public key is not EC");
    }

    value = key;

    // Copy public data

    CopyObjectAttribute(this, pPubKey, CKA_ID);
    CopyObjectAttribute(this, pPubKey, CKA_EC_PARAMS);

    ItemByType(CKA_SIGN)->To<core::AttributeBool>()->Set(pPubKey->ItemByType(CKA_VERIFY)->ToBool());
    ItemByType(CKA_DERIVE)->To<core::AttributeBool>()->Set(pPubKey->ItemByType(CKA_DERIVE)->ToBool());
  }
  CATCH_EXCEPTION
}

void osx::EcPrivateKey::Assign(SecAttributeDictionary *attrs)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    value = attrs->GetValueRef()->To<SecKey>();

    // Check key type
    Scoped<CFString> cfKeyType = attrs->GetValue(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->Compare(kSecAttrKeyTypeEC, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
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

    CK_ULONG keySizeInBits = 0;
    Scoped<CFNumber> cfKeySizeInBits = attrs->GetValue(kSecAttrKeySizeInBits)->To<CFNumber>();
    cfKeySizeInBits->GetValue(kCFNumberSInt32Type, &keySizeInBits);

    SetECParams(keySizeInBits);
  }
  CATCH_EXCEPTION
}

void osx::EcPrivateKey::SetECParams(CK_ULONG keySizeInBits)
{
  switch (keySizeInBits)
  {
  case 256:
    ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, sizeof(core::EC_P256_BLOB) - 1);
    break;
  case 384:
    ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, sizeof(core::EC_P384_BLOB) - 1);
    break;
  case 521:
    ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, sizeof(core::EC_P521_BLOB) - 1);
    break;
  default:
    THROW_EXCEPTION("Unsupported size of key");
  }
}

CK_RV osx::EcPrivateKey::CopyValues(
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

CK_RV osx::EcPrivateKey::Destroy()
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

void osx::EcPrivateKey::FillPublicKeyStruct()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    CFRef<SecKeyRef> publicKey = SecKeyCopyPublicKeyEx(value->Get());

    if (publicKey.IsEmpty())
    {
      // Cannot contain a public key or no public key can be computed from this private key
      THROW_EXCEPTION("Error on SecKeyCopyPublicKeyEx");
    }

    CFDictionary cfAttributes = SecKeyCopyAttributesEx(*publicKey);
    if (cfAttributes.IsEmpty())
    {
      THROW_EXCEPTION("Error on SecKeyCopyAttributesEx");
    }

    Scoped<CFString> cfLabel = cfAttributes.GetValueOrNull(kSecAttrLabel)->To<CFString>();
    if (!cfLabel->IsEmpty())
    {
      ItemByType(CKA_LABEL)->To<core::AttributeBytes>()->SetValue(
          (CK_BYTE_PTR)cfLabel->GetCString()->c_str(),
          cfLabel->GetCString()->size());
    }

    CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(*cfAttributes, kSecAttrKeySizeInBits);
    if (!cfKeySizeInBits)
    {
      THROW_EXCEPTION("Cannot get size of key");
    }
    CK_ULONG keySizeInBits = 0;

    CFNumberType cfNumberType = CFNumberGetType(cfKeySizeInBits);
    if (!CFNumberGetValue(cfKeySizeInBits, cfNumberType, &keySizeInBits))
    {
      THROW_EXCEPTION("Error on CFNumberGetValue");
    }
    Scoped<CFData> cfKeyData = value->GetExternalRepresentation();

    SetECParams(keySizeInBits);
  }
  CATCH_EXCEPTION
}

void osx::EcPrivateKey::FillPrivateKeyStruct()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    // Get public key SEQUENCE
    Scoped<CFData> cfKeyData = value->GetExternalRepresentation();

    // Get attributes of key
    CFRef<CFDictionaryRef> cfAttributes = SecKeyCopyAttributesEx(value->Get());
    if (cfAttributes.IsEmpty())
    {
      THROW_EXCEPTION("Error on SecKeyCopyAttributes");
    }

    // Get key size
    CFNumberRef cfKeySizeInBits = (CFNumberRef)CFDictionaryGetValue(*cfAttributes, kSecAttrKeySizeInBits);
    if (!cfKeySizeInBits)
    {
      THROW_EXCEPTION("Cannot get size of key");
    }
    CK_ULONG keySizeInBits = 0;
    CFNumberGetValue(cfKeySizeInBits, kCFNumberSInt64Type, &keySizeInBits);
    keySizeInBits = (keySizeInBits + 7) >> 3;

    // Get private part of the key
    ItemByType(CKA_VALUE)->SetValue((CK_VOID_PTR)(cfKeyData->GetBytePtr() + (keySizeInBits * 2)),
                                    keySizeInBits);
  }
  CATCH_EXCEPTION
}

CK_RV osx::EcPrivateKey::GetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    switch (attr->type)
    {
    case CKA_EC_PARAMS:
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillPublicKeyStruct();
      }
      break;
    case CKA_VALUE:
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillPrivateKeyStruct();
      }
      break;
    default:
      return core::EcPrivateKey::GetValue(attr);
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

// RsaPublicKey

CK_RV osx::EcPublicKey::CreateValues(
    CK_ATTRIBUTE_PTR pTemplate, /* specifies attributes */
    CK_ULONG ulCount            /* attributes in template */
)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::EcPublicKey::CreateValues(pTemplate, ulCount);

    core::Template tmpl(pTemplate, ulCount);

    // POINT
    Scoped<Buffer> point = tmpl.GetBytes(CKA_EC_POINT, true);
    // PARAMS
    Scoped<Buffer> params = tmpl.GetBytes(CKA_EC_PARAMS, true);

    Scoped<CFData> publicData = CFData::Create(kCFAllocatorDefault, point->data(), point->size());
    Scoped<CFData> keyData = GetKeyDataFromOctetString(publicData->Get());

    const UInt8 *keyDataBytes = keyData->GetBytePtr();
    CFIndex keyDataLength = keyData->GetLength();
    Scoped<CFData> spki = SetKeyDataToPublicKey((UInt8 *)keyDataBytes, keyDataLength);
    if (spki->IsEmpty())
    {
      THROW_EXCEPTION("Error on SetKeyDataToPublicKey");
    }

    Scoped<CFMutableDictionary> keyAttr = CFMutableDictionary::Create();
    keyAttr
        ->AddValue(kSecAttrKeyType, kSecAttrKeyTypeEC)
        ->AddValue(kSecAttrKeyClass, kSecAttrKeyClassPublic);

    // Set key usage
    if (tmpl.GetBool(CKA_VERIFY, false))
    {
      keyAttr->AddValue(kSecAttrCanVerify, kCFBooleanTrue);
    }

    Scoped<SecKey> publicKey = SecKey::CreateFromData(keyAttr->Get(),
                                                      spki->Get());

    Assign(publicKey);

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

CK_RV osx::EcPublicKey::CopyValues(
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

CK_RV osx::EcPublicKey::Destroy()
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

void osx::EcPublicKey::Assign(Scoped<SecKey> key)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (key == NULL)
    {
      THROW_EXCEPTION("SecKeyRef is empty");
    }

    value = key;

    Scoped<CFDictionary> cfAttributes = value->GetAttributes();

    // Check key type
    Scoped<CFString> cfKeyType = cfAttributes->GetValueOrNull(kSecAttrKeyType)->To<CFString>();
    if (cfKeyType->IsEmpty())
    {
      THROW_EXCEPTION("Key item doesn't have kSecAttrKeyType attribute");
    }
    if (cfKeyType->Compare(kSecAttrKeyTypeEC, kCFCompareCaseInsensitive) != kCFCompareEqualTo)
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
    if (!cfAppLabel->IsEmpty())
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

    FillKeyStruct();
  }
  CATCH_EXCEPTION
}

void osx::EcPublicKey::FillKeyStruct()
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    Scoped<CFDictionary> cfAttributes = value->GetAttributes();

    // Get key size
    Scoped<CFNumber> cfKeySizeInBits = cfAttributes->GetValueOrNull(kSecAttrKeySizeInBits)->To<CFNumber>();
    if (cfKeySizeInBits->IsEmpty())
    {
      THROW_EXCEPTION("Cannot get size of the key");
    }
    CK_ULONG keySizeInBits = 0;
    CFNumberGetValue(cfKeySizeInBits->Get(), kCFNumberSInt64Type, &keySizeInBits);

    Scoped<std::string> propPoint(new std::string(""));
    switch (keySizeInBits)
    {
    case 256:
      ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P256_BLOB, sizeof(core::EC_P256_BLOB) - 1);
      *propPoint += std::string("\x04\x41");
      break;
    case 384:
      ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P384_BLOB, sizeof(core::EC_P384_BLOB) - 1);
      *propPoint += std::string("\x04\x61");
      break;
    case 521:
      ItemByType(CKA_EC_PARAMS)->SetValue((CK_VOID_PTR)core::EC_P521_BLOB, sizeof(core::EC_P521_BLOB) - 1);
      *propPoint += std::string("\x04\x81\x85");
      break;
    default:
      THROW_EXCEPTION("Unsupported size of key");
    }

    Scoped<CFData> cfKeyData = NULL;
    try
    {
      cfKeyData = value->GetExternalRepresentation();
    }
    catch (Scoped<core::Exception> e)
    {
      // LOGGER_WARN("Cannot export EC public key. %s", e->message.c_str());
    }

    if (cfKeyData.get() != nullptr)
    {
      *propPoint += std::string((char *)cfKeyData->GetBytePtr(), cfKeyData->GetLength());
      ItemByType(CKA_EC_POINT)->SetValue((CK_BYTE_PTR)propPoint->c_str(), propPoint->length());
    }
    else
    {
      CK_BYTE modulus[0] = {};
      ItemByType(CKA_EC_POINT)->SetValue(modulus, 0);
    }
  }
  CATCH_EXCEPTION
}

CK_RV osx::EcPublicKey::GetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    switch (attr->type)
    {
    case CKA_EC_PARAMS:
    case CKA_EC_POINT:
      if (ItemByType(attr->type)->IsEmpty())
      {
        FillKeyStruct();
      }
      break;
    default:
      return core::EcPublicKey::GetValue(attr);
    }

    return CKR_OK;
  }
  CATCH_EXCEPTION
}
