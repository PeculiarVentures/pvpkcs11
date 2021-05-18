#include "keychain.h"

using namespace osx;

Scoped<SecKeychain> SecKeychain::CreateEmpty()
{
  return Scoped<SecKeychain>(new SecKeychain);
}

Scoped<SecKeychain> SecKeychain::GetDefault()
{
  Scoped<SecKeychain> keychain = SecKeychain::CreateEmpty();

  OSStatus status = SecKeychainCopyDefault(keychain->Ref());
  if (status)
  {
    THROW_OSX_EXCEPTION(status, "SecKeychainCopyDefault");
  }

  return keychain;
}

Scoped<CFArray> SecKeychain::GetItems(CFStringRef matchType)
{
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
    THROW_OSX_EXCEPTION(status, "SecItemCopyMatching");
  }

  return result;
}

Scoped<CFArray> SecKeychain::GetCertificates()
{
  return GetItems(kSecClassCertificate);
}

Scoped<CFArray> SecKeychain::GetIdentities()
{
  return GetItems(kSecClassIdentity);
}

Scoped<CFArray> SecKeychain::GetKeys()
{
  return GetItems(kSecClassKey);
}
