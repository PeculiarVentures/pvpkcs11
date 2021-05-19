#include "data.h"

#include "crypto.h"
#include "sec.h"
#include "x509_request_template.h"

using namespace osx;

void osx::Data::Assign(
    Scoped<Buffer> data)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
  }
  CATCH_EXCEPTION
}

CK_RV osx::Data::CreateValues(
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
  try
  {
    core::Data::CreateValues(
        pTemplate,
        ulCount);

    
    core::Template tmpl(pTemplate, ulCount);
    Scoped<Buffer> attrValue = tmpl.GetBytes(CKA_VALUE, true);

    // Decode ASN1 structure
    Scoped<osx::SecAsn1Coder> coder = osx::SecAsn1Coder::Create();

    ASN1_X509_REQUEST asn1Request;
    coder->DecodeItem(attrValue->data(), attrValue->size(), kX509RequestTemplate, &asn1Request);

    // Copy SPKI data to buffer
    SecAsn1Item spki = asn1Request.certificationRequestInfo.subjectPublicKeyInfo.subjectPublicKey;
    Scoped<Buffer> spkiBuf(new Buffer(spki.Length >> 3));
    memcpy(spkiBuf->data(), spki.Data, spkiBuf->size());

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

CK_RV osx::Data::CopyValues(
    Scoped<Object> object,
    CK_ATTRIBUTE_PTR pTemplate,
    CK_ULONG ulCount)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    core::Data::CopyValues(
        object,
        pTemplate,
        ulCount);

    core::Template tmpl(pTemplate, ulCount);

    return CKR_OK;
  }
  CATCH_EXCEPTION
}

CK_RV osx::Data::CreateValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (attr)
    {
      // Don't change value
      if (attr->type == CKA_OBJECT_ID)
      {
        return CKR_OK;
      }
    }

    return core::Data::CreateValue(attr);
  }
  CATCH_EXCEPTION
}

CK_RV osx::Data::CopyValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (attr)
    {
      // Don't change value
      if (attr->type == CKA_OBJECT_ID)
      {
        return CKR_OK;
      }
    }

    return core::Data::CopyValue(attr);
  }
  CATCH_EXCEPTION
}

CK_RV osx::Data::SetValue(
    CK_ATTRIBUTE_PTR attr)
{
  LOGGER_FUNCTION_BEGIN;

  try
  {
    if (attr)
    {
      // Don't change value
      if (attr->type == CKA_OBJECT_ID)
      {
        return CKR_OK;
      }
    }

    return core::Data::SetValue(attr);
  }
  CATCH_EXCEPTION
}

CK_RV osx::Data::Destroy()
{
  try
  {
    return CKR_OK;
  }
  CATCH_EXCEPTION
}
