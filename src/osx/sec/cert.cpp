#include "cert.h"

using namespace osx;

Scoped<SecCertificate> SecCertificate::CreateRetain(SecCertificateRef cert)
{
  FUNCTION_BEGIN

  SecCertificateRef cert2 = (SecCertificateRef)CFRetain(cert);

  return Scoped<SecCertificate>(new SecCertificate(cert2));

  FUNCTION_END
}

Scoped<CFString> SecCertificate::GetCommonName()
{
  FUNCTION_BEGIN

  Scoped<CFString> str = Scoped<CFString>(new CFString);

  OSStatus status = SecCertificateCopyCommonName(handle, str->Ref());
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecCertificateCopyCommonName");
  }

  return str;

  FUNCTION_END
}

Scoped<CFData> SecCertificate::GetData()
{
  FUNCTION_BEGIN

  CFDataRef data = SecCertificateCopyData(handle);

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Scoped<CFData> SecCertificate::GetNormalizedIssuerSequence()
{
  FUNCTION_BEGIN

  CFDataRef data = SecCertificateCopyNormalizedIssuerSequence(handle);

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Scoped<CFData> SecCertificate::GetNormalizedSubjectSequence()
{
  FUNCTION_BEGIN

  CFDataRef data = SecCertificateCopyNormalizedSubjectSequence(handle);

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Scoped<CFData> SecCertificate::GetSerialNumberData()
{
  FUNCTION_BEGIN

  CFError error;
  CFDataRef data = SecCertificateCopySerialNumberData(handle, &error);

  if (!error.IsEmpty())
  {
    Scoped<CFString> errorText = error.GetDescription();
    THROW_EXCEPTION(errorText->GetCString()->c_str());
  }

  return Scoped<CFData>(new CFData(data));

  FUNCTION_END
}

Scoped<SecCertificate> SecCertificate::CreateWithData(CFAllocatorRef allocator, CFDataRef data)
{
  FUNCTION_BEGIN

  SecCertificateRef cert = SecCertificateCreateWithData(allocator, data);
  if (!cert)
  {
    THROW_EXCEPTION("Error on SecCertificateCreateWithData. Cannot create SecCertificate from CFData");
  }

  return Scoped<SecCertificate>(new SecCertificate(cert));

  FUNCTION_END
}

void SecCertificate::AddToKeychain(SecKeychainRef keyChain)
{
  FUNCTION_BEGIN

  OSStatus status = SecCertificateAddToKeychain(handle, keyChain);

  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecCertificateAddToKeychain");
  }

  FUNCTION_END
}

Scoped<SecKey> SecCertificate::GetPublicKey()
{
  FUNCTION_BEGIN

  SecKeyRef key = SecCertificateCopyKey(handle);

  if (!key)
  {
    THROW_EXCEPTION("SecCertificateCopyKey");
  }

  return Scoped<SecKey>(new SecKey(key));

  FUNCTION_END
}

Scoped<CFString> SecCertificate::GetSubjectSummary()
{
  FUNCTION_BEGIN

  CFStringRef str = SecCertificateCopySubjectSummary(handle);

  return Scoped<CFString>(new CFString(str));

  FUNCTION_END
}

Scoped<CFDictionary> SecCertificate::GetValues(CFArrayRef keys)
{
  FUNCTION_BEGIN

  CFError error;

  CFDictionaryRef ref = SecCertificateCopyValues(handle, keys, &error);
  if (!error.IsEmpty())
  {
    THROW_EXCEPTION(error.GetDescription()->GetCString()->c_str());
  }
  if (ref == NULL)
  {
    THROW_EXCEPTION("Error on SecCertificateCopyValues");
  }

  return Scoped<CFDictionary>(new CFDictionary(ref));

  FUNCTION_END
}
