#include "crypt.h"

using namespace crypt;

Scoped<Cipher> Cipher::Create(
	bool        encrypt,
	Scoped<Key> key
)
{
	try {
		return Scoped<Cipher>(new Cipher(encrypt, key));
	}
	CATCH_EXCEPTION;
}

Cipher::Cipher(
	bool        encrypt,
	Scoped<Key> key
) :
	encrypt(encrypt),
	key(key)
{
	try {
		blockLen = key->GetBlockLen();
		buffer = std::string("");
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Cipher::Update(
	BYTE*  pbData,
	DWORD  dwDataLen
)
{
	try {
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
	CATCH_EXCEPTION;
}

Scoped<std::string> Cipher::Final()
{
	try {
		if (encrypt || !buffer.empty()) {
			return this->Make(true, (BYTE*)buffer.c_str(), buffer.length());
		}
		else {
			return Scoped<std::string>(new std::string());
		}
	}
	CATCH_EXCEPTION;
}

Scoped<std::string> Cipher::Make(
	bool   bFinal,
	BYTE*  pbData,
	DWORD  dwDataLen
)
{
	try {
		Scoped<std::string> result(new std::string((char*)pbData, dwDataLen));
		DWORD dwEncryptedLen = dwDataLen;

		if (encrypt) {
			if (bFinal) {
				// Get size for returned block
				if (!CryptEncrypt(key->Get(), NULL, bFinal, 0, NULL, &dwEncryptedLen, dwDataLen)) {
					THROW_MSCAPI_ERROR();
				}
				result->resize(dwEncryptedLen);
			}
			// Get cipher text
			if (!CryptEncrypt(key->Get(), NULL, bFinal, 0, (BYTE*)result->c_str(), &dwDataLen, dwEncryptedLen)) {
				THROW_MSCAPI_ERROR();
			}
		}
		else {
			if (bFinal) {
				dwEncryptedLen = blockLen;
				result->resize(dwEncryptedLen);
			}
			if (!CryptDecrypt(key->Get(), NULL, bFinal, 0, dwDataLen ? (BYTE*)result->c_str() : NULL, &dwEncryptedLen)) {
				THROW_MSCAPI_ERROR();
			}
			// Remove padding for AES-CBC with PKCS5 padding
			if (key->GetAlgId() & CALG_AES && key->GetMode() == CRYPT_MODE_CBC && key->GetPadding() == PKCS5_PADDING) {
				dwEncryptedLen -= result->back();
			}
			result->resize(dwEncryptedLen);
		}

		return result;
	}
	CATCH_EXCEPTION;
}