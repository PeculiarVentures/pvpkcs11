#include "aes_key.h"
#include "../core/template.h"

MscapiAesKey::MscapiAesKey()
{
	handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
}

void MscapiAesKey::SetCryptoKey(Scoped<crypt::Key> value)
{
	try {
		this->value = value;
		this->propValueLen = value->GetKeyLen();
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiAesKey::GetValue)
{
	try {
		CK_RV res = AesKey::GetValue(pValue, pulValueLen);
		if (res != CKR_ATTRIBUTE_TYPE_INVALID) {
			return res;
		}

		res = CKR_OK;

		DWORD dwDataLen = 0;
		std::string strData("");
		BYTE* pbData = NULL;

		if (!CryptExportKey(this->value->Get(), NULL, PLAINTEXTKEYBLOB, 0, NULL, &dwDataLen)) {
			THROW_MSCAPI_ERROR();
		}
		strData.resize(dwDataLen);
		pbData = (BYTE*)strData.c_str();
		if (!CryptExportKey(this->value->Get(), NULL, PLAINTEXTKEYBLOB, 0, pbData, &dwDataLen)) {
			THROW_MSCAPI_ERROR();
		}

		BLOBHEADER* blobHeader = (BLOBHEADER*)pbData;
		DWORD* pdwKeySize = (DWORD*)(pbData + sizeof(BLOBHEADER));
		BYTE* pbKeyValue = (BYTE*)(pbData + sizeof(BLOBHEADER) + sizeof(DWORD));

		// reverse bytes
		std::reverse(&pbKeyValue[0], &pbKeyValue[*pdwKeySize]);

		res = this->GetBytes(pValue, pulValueLen, pbKeyValue, *pdwKeySize);

		return res;
	}
	CATCH_EXCEPTION;
}

Scoped<Object> MscapiAesKey::GenerateKey
(
	CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
	CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
	CK_ULONG             ulCount     /* # of attrs in template */
)
{
	try {
		// Get values from template
		Template tmpl(pTemplate, ulCount);

		Scoped<MscapiAesKey> aesKey(new MscapiAesKey());

		// Required attributes
		aesKey->propValueLen = tmpl.GetNumber(CKA_VALUE_LEN, true) * 8;
		switch (aesKey->propValueLen) {
		case 128:
		case 192:
		case 256:
			break;
		default:
			THROW_PKCS11_EXCEPTION(CKR_MECHANISM_INVALID, "AES value length must be 128, 192 or 256");
		}

		// Optional attributes
		aesKey->propExtractable = tmpl.GetBool(CKA_EXTRACTABLE, false, false);
		aesKey->propToken = tmpl.GetBool(CKA_TOKEN, false, false);
		if (aesKey->propToken) {
			THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "AES doesn't support TOKEN(true)");
		}
		aesKey->propId = *tmpl.GetBytes(CKA_ID, false, "");
		aesKey->propEncrypt = tmpl.GetBool(CKA_ENCRYPT, false, false);
		aesKey->propDecrypt = tmpl.GetBool(CKA_DECRYPT, false, false);
		aesKey->propSign = tmpl.GetBool(CKA_SIGN, false, false);
		aesKey->propVerify = tmpl.GetBool(CKA_VERIFY, false, false);

		Scoped<crypt::Provider> prov = crypt::Provider::Create(NULL, NULL, PROV_RSA_AES, 0);
		DWORD dwFlags = 0;
		if (aesKey->propExtractable) {
			dwFlags |= CRYPT_EXPORTABLE;
		}
		Scoped<crypt::Key> key = crypt::Key::Generate(prov, CALG_AES_256, dwFlags);
		aesKey->SetCryptoKey(key);


		return aesKey;
	}
	CATCH_EXCEPTION;
}