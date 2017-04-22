#include "crypt.h"

using namespace crypt;

Scoped<Cipher> Cipher::Create(
	bool        encrypt,
	Scoped<Key> key
)
{
	return Scoped<Cipher>(new Cipher(encrypt, key));
}

Cipher::Cipher(
	bool        encrypt,
	Scoped<Key> key
) :
	encrypt(encrypt),
	key(key)
{
	blockLen = key->GetBlockLen();
	buffer = std::string();
}

Scoped<std::string> Cipher::Update(
	BYTE*  pbData,
	DWORD  dwDataLen
)
{
	puts(__FUNCTION__);
	std::string data("");
	std::string incomingData((char*)pbData, dwDataLen);
	data = buffer + incomingData;
	DWORD dwModulo = data.length() % blockLen;
	if (dwModulo) {
		buffer = data.substr(data.length() - dwModulo, dwModulo);
		data.resize(data.length() - dwModulo);
	}
	else {
		buffer.erase();
	}
	Scoped<std::string> result(new std::string(""));
	if (data.length()) {
		result = this->Make(false, (BYTE*)data.c_str(), data.length());
	}
	return result;
}

Scoped<std::string> Cipher::Final()
{
	puts(__FUNCTION__);
	return this->Make(true, (BYTE*)buffer.c_str(), buffer.length());
}

Scoped<std::string> Cipher::Make(
	bool   bFinal,
	BYTE*  pbData,
	DWORD  dwDataLen
)
{
	Scoped<std::string> result(new std::string((char*)pbData, dwDataLen));
	DWORD dwEncryptedLen = dwDataLen;

	if (encrypt) {
		if (bFinal) {
			// Get size for returned block
			if (!CryptEncrypt(key->Get(), NULL, bFinal, 0, NULL, &dwEncryptedLen, dwDataLen)) {
				// THROW_MS_ERROR();
			}
			result->resize(dwEncryptedLen);
		}
		// Get cipher text
		if (!CryptEncrypt(key->Get(), NULL, bFinal, 0, (BYTE*)result->c_str(), &dwDataLen, dwEncryptedLen)) {
			THROW_MS_ERROR();
		}
	}
	else {
		if (bFinal) {
			dwEncryptedLen = blockLen;
			result->resize(dwEncryptedLen);
		}
		if (!CryptDecrypt(key->Get(), NULL, bFinal, 0, dwDataLen ? (BYTE*)result->c_str() : NULL, &dwEncryptedLen)) {
			THROW_MS_ERROR();
		}
		result->resize(dwEncryptedLen);
	}

	return result;
}