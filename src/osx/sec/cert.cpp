#include "cert.h"

using namespace osx;

Scoped<SecCertificate> SecCertificate::CreateRetain(SecCertificateRef cert)
{
  SecCertificateRef cert2 = (SecCertificateRef)CFRetain(cert);

  return Scoped<SecCertificate>(new SecCertificate(cert2));
}

Scoped<CFString> SecCertificate::GetCommonName()
{
  Scoped<CFString> str = Scoped<CFString>(new CFString);

  OSStatus status = SecCertificateCopyCommonName(handle, str->Ref());
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecCertificateCopyCommonName");
  }

  return str;
}

Scoped<CFData> SecCertificate::GetData()
{
  CFDataRef data = SecCertificateCopyData(handle);

  return Scoped<CFData>(new CFData(data));
}

Scoped<CFData> SecCertificate::GetNormalizedIssuerSequence()
{
  CFDataRef data = SecCertificateCopyNormalizedIssuerSequence(handle);

  return Scoped<CFData>(new CFData(data));
}

Scoped<CFData> SecCertificate::GetNormalizedSubjectSequence()
{
  CFDataRef data = SecCertificateCopyNormalizedSubjectSequence(handle);

  return Scoped<CFData>(new CFData(data));
}

Scoped<CFData> SecCertificate::GetSerialNumberData()
{
  CFError error;
  CFDataRef data = SecCertificateCopySerialNumberData(handle, &error);

  if (!error.IsEmpty())
  {
    Scoped<CFString> errorText = error.GetDescription();
    THROW_EXCEPTION(errorText->GetCString()->c_str());
  }

  return Scoped<CFData>(new CFData(data));
}

Scoped<SecCertificate> SecCertificate::CreateWithData(CFAllocatorRef allocator, CFDataRef data)
{
  SecCertificateRef cert = SecCertificateCreateWithData(allocator, data);
  if (!cert)
  {
    THROW_EXCEPTION("Cannot create Certificate from CFData");
  }

  return Scoped<SecCertificate>(new SecCertificate(cert));
}

void SecCertificate::AddToKeychain(SecKeychainRef keyChain)
{
  OSStatus status = SecCertificateAddToKeychain(handle, keyChain);

  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecCertificateAddToKeychain");
  }
}

Scoped<SecKey> SecCertificate::GetPublicKey()
{
  SecKeyRef key = SecCertificateCopyKey(handle);

  if (!key)
  {
    THROW_EXCEPTION("SecCertificateCopyKey");
  }

  return Scoped<SecKey>(new SecKey(key));
}

Scoped<CFString> SecCertificate::GetSubjectSummary()
{
  CFStringRef str = SecCertificateCopySubjectSummary(handle);

  return Scoped<CFString>(new CFString(str));
}

Scoped<CFDictionary> SecCertificate::GetValues(CFArrayRef keys)
{
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
}
