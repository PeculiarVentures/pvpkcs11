#include "keychain.h"

using namespace osx;

Scoped<SecKeychain> SecKeychain::CreateEmpty()
{
  FUNCTION_BEGIN

  return Scoped<SecKeychain>(new SecKeychain);

  FUNCTION_END
}

Scoped<SecKeychain> SecKeychain::GetDefault()
{
  FUNCTION_BEGIN

  Scoped<SecKeychain> keychain = SecKeychain::CreateEmpty();

  OSStatus status = SecKeychainCopyDefault(keychain->Ref());
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecKeychainCopyDefault");
  }

  return keychain;

  FUNCTION_END
}

Scoped<SecKeychain> SecKeychain::Open(const char * path)
{
  FUNCTION_BEGIN

  SecKeychainRef keychain = nullptr;

  OSStatus status = SecKeychainOpen(path, &keychain);
  
  if (status) {
    THROW_OSX_EXCEPTION(status, "SecKeychainOpen");
  }

  return Scoped<SecKeychain>(new SecKeychain(keychain));

  FUNCTION_END
}

Scoped<CFArray> SecKeychain::GetItems(CFStringRef matchType)
{
  FUNCTION_BEGIN

  Scoped<CFArray> result = Scoped<CFArray>(new CFArray);
  Scoped<CFMutableDictionary> query = CFMutableDictionary::Create();
  Scoped<CFArray> searchList = CFArray::Create(
      kCFAllocatorDefault, const_cast<const void **>(reinterpret_cast<void **>(&handle)), 1, &kCFTypeArrayCallBacks);

  query
      ->AddValue(kSecReturnRef, kCFBooleanTrue)
      ->AddValue(kSecMatchLimit, kSecMatchLimitAll)
      ->AddValue(kSecReturnAttributes, kCFBooleanTrue)
      ->AddValue(kSecClass, matchType)
      ->AddValue(kSecMatchSearchList, searchList->Get());

  OSStatus status = SecItemCopyMatching(query->Get(), reinterpret_cast<CFTypeRef *>(result->Ref()));
  if (status)
  {
    if (status == errSecItemNotFound) {
      return CFArray::Create(kCFAllocatorDefault, NULL, 0, &kCFTypeArrayCallBacks);
    }

    THROW_OSX_EXCEPTION(status, "SecItemCopyMatching");
  }

  return result;
  
  FUNCTION_END
}

Scoped<CFArray> SecKeychain::GetCertificates()
{
  FUNCTION_BEGIN

  return GetItems(kSecClassCertificate);

  FUNCTION_END
}

Scoped<CFArray> SecKeychain::GetIdentities()
{
  FUNCTION_BEGIN

  return GetItems(kSecClassIdentity);

  FUNCTION_END
}

Scoped<CFArray> SecKeychain::GetKeys()
{
  FUNCTION_BEGIN
  
  return GetItems(kSecClassKey);

  FUNCTION_END
}
