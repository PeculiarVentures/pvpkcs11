#include "identity.h"

using namespace osx;

Scoped<SecCertificate> SecIdentity::GetCertificate()
{
  Scoped<SecCertificate> cert = Scoped<SecCertificate>(new SecCertificate);

  OSStatus status = SecIdentityCopyCertificate(handle, cert->Ref());
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecIdentityCopyCertificate");
  }

  return cert;
}

Scoped<SecKey> SecIdentity::GetPrivateKey()
{
  Scoped<SecKey> key = Scoped<SecKey>(new SecKey);

  OSStatus status = SecIdentityCopyPrivateKey(handle, key->Ref());
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecIdentityCopyPrivateKey");
  }

  return key;
}