#include "asn1_coder.h"

using namespace osx;

Scoped<osx::SecAsn1Coder> osx::SecAsn1Coder::Create()
{
  FUNCTION_BEGIN

  return Scoped<osx::SecAsn1Coder>(new osx::SecAsn1Coder);

  FUNCTION_END
}

osx::SecAsn1Coder::SecAsn1Coder() : handle(NULL)
{
  FUNCTION_BEGIN 

  OSStatus status = SecAsn1CoderCreate(&handle);
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecAsn1CoderCreate");
  }

  FUNCTION_END
}

osx::SecAsn1Coder::~SecAsn1Coder()
{
  FUNCTION_BEGIN

  Release();

  FUNCTION_END
}

SecAsn1Item osx::SecAsn1Coder::FromCFData(CFData *data)
{
  FUNCTION_BEGIN

  SecAsn1Item res;

  res.Data = (uint8_t *)data->GetBytePtr();
  res.Length = data->GetLength();

  return res;

  FUNCTION_END
}

SecAsn1Item osx::SecAsn1Coder::EncodeItem(const void *src, const SecAsn1Template *templates)
{
  FUNCTION_BEGIN

  SecAsn1Item dest;

  OSStatus status = SecAsn1EncodeItem(handle, src, templates, &dest);
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecAsn1EncodeItem");
  }

  return dest;

  FUNCTION_END
}

void osx::SecAsn1Coder::DecodeItem(
    const void *src, // DER-encoded source
    size_t len,
    const SecAsn1Template *templates,
    void *dest)
{
  FUNCTION_BEGIN

  OSStatus status = SecAsn1Decode(handle, src, len, templates, dest);
  
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecAsn1Decode");
  }

  FUNCTION_END
}

void osx::SecAsn1Coder::Release()
{
  FUNCTION_BEGIN

  if (handle)
  {
    OSStatus status = SecAsn1CoderRelease(handle);

    if (status)
    {
      THROW_OSX_EXCEPTION(status, "SecAsn1CoderRelease");
    }

    handle = NULL;
  }

  FUNCTION_END
}