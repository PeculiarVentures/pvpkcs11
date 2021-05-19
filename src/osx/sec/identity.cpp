#include "identity.h"

using namespace osx;

Scoped<SecIdentity> SecIdentity::CreateWithCertificate(CFTypeRef keychainOrArray, SecCertificateRef cert)
{
  FUNCTION_BEGIN

    SecIdentity identity;

    OSStatus status = SecIdentityCreateWithCertificate(keychainOrArray, cert, identity.Ref());
    if (status) {
      THROW_OSX_EXCEPTION(status, "SecIdentityCreateWithCertificate");
    }

    return identity.To<SecIdentity>();
  
  FUNCTION_END
}

Scoped<SecCertificate> SecIdentity::GetCertificate()
{
  FUNCTION_BEGIN

  Scoped<SecCertificate> cert = Scoped<SecCertificate>(new SecCertificate);

  OSStatus status = SecIdentityCopyCertificate(handle, cert->Ref());
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecIdentityCopyCertificate");
  }

  return cert;

  FUNCTION_END
}

Scoped<SecKey> SecIdentity::GetPrivateKey()
{
  FUNCTION_BEGIN

  Scoped<SecKey> key = Scoped<SecKey>(new SecKey);

  OSStatus status = SecIdentityCopyPrivateKey(handle, key->Ref());
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecIdentityCopyPrivateKey");
  }

  return key;

  FUNCTION_END
}