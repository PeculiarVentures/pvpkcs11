#include "../stdafx.h"
#include "helper.h"
#include "session.h"
#include "certificate.h"
#include "rsa_public_key.h"
#include "rsa_private_key.h"
#include "helper.h"

static void TestPrintContainers(DWORD provType)
{
	// Print containers
	Scoped<crypt::Provider> prov = crypt::Provider::Create(NULL, NULL, provType, 0);
	auto containers = prov->GetContainers();
	fprintf(stdout, "Containers amount %u\n", containers->count());
	for (int i = 0; i < containers->count(); i++) {
		puts(containers->items(i)->c_str());
	}
}

#define PRINT_ERROR() \
    PRINT_WIN_ERROR(); fprintf(stdout, "%s:%d\n", __FILE__,__LINE__); throw std::exception("Oops");

static void TestCipher() {
	Scoped<crypt::Provider> prov = crypt::Provider::Create(NULL, NULL, PROV_RSA_AES, 0);
	// Scoped<crypt::Key> key = crypt::Key::Generate(prov, CALG_AES_256, 0);
	BYTE aesKey[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2 };
	BYTE aesIv[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6 };
	struct aes256keyBlob
	{
		BLOBHEADER hdr;
		DWORD keySize;
		BYTE bytes[32];
	} blob;

	blob.hdr.bType = PLAINTEXTKEYBLOB;
	blob.hdr.bVersion = CUR_BLOB_VERSION;
	blob.hdr.reserved = 0;
	blob.hdr.aiKeyAlg = CALG_AES_256;
	blob.keySize = 32;
	memcpy(blob.bytes, aesKey, 32);
	Scoped<crypt::Key> key = crypt::Key::Import(prov, (BYTE*)&blob, sizeof(aes256keyBlob), 0);
	Scoped<crypt::Key> key1 = key->Copy();
	Scoped<crypt::Key> key2 = key->Copy();
	key1->SetIV(aesIv, 16);
	key2->SetIV(aesIv, 16);


	auto cipher = crypt::Cipher::Create(true, key1);
	auto decipher = crypt::Cipher::Create(false, key2);

	auto encData = cipher->Update((BYTE*)"first", 5);
	fprintf(stdout, "Encrypted length: %d\n", encData->length());
	*encData.get() += *cipher->Update((BYTE*)"second", 6).get();
	fprintf(stdout, "Encrypted length: %d\n", encData->length());
	*encData.get() += *cipher->Update((BYTE*)"12345678901234567890", 20).get();
	fprintf(stdout, "Encrypted length: %d\n", encData->length());
	*encData.get() += *cipher->Final().get();
	fprintf(stdout, "Encrypted length: %d\n", encData->length());
	fprintf(stdout, "Encrypted: ");
	for (int i = 0; i < encData->length(); i++) {
		fprintf(stdout, "%02x", (unsigned char)encData->c_str()[i]);
	}
	fprintf(stdout, "\n");

	auto decData = decipher->Update((BYTE*)encData->c_str(), encData->length());
	*decData += *decipher->Final();
	fprintf(stdout, "Decrypted length: %d\n", decData->length());
	fprintf(stdout, "Decrypted: %s\n", decData->c_str());


	// *decData += *decipher->Final();
	// fprintf(stdout, "Decrypted: %s\n", decData->c_str());
}

MscapiSession::MscapiSession() : Session()
{
	hRsaAesProv = NULL;
}


MscapiSession::~MscapiSession()
{
	if (hRsaAesProv) {
		CryptReleaseContext(hRsaAesProv, 0);
		hRsaAesProv = NULL;
	}
}

void MscapiSession::LoadMyStore()
{
	Scoped<crypt::CertStore> store(new crypt::CertStore());
	this->certStores.add(store);
	store->Open("My");
	Scoped<Collection<Scoped<crypt::X509Certificate>>> certs = store->GetCertificates();
	for (size_t i = 0; i < certs->count(); i++) {
		Scoped<crypt::X509Certificate> x509 = certs->items(i);
		Scoped<MscapiCertificate> x509Object(new MscapiCertificate(x509, true));

		// Get public key for Certificate. Application supports RSA and EC algorithms
		// In other case application throws error
		Scoped<Object> publicKeyObject;
		try {
			Scoped<crypt::Key> publicKey = x509->GetPublicKey();
			fprintf(stdout, "Certificate '%s' has public key\n", x509->GetLabel()->c_str());
			Scoped<MscapiRsaPublicKey> key(new MscapiRsaPublicKey(publicKey, true));
			key->id = *x509->GetHashPublicKey().get();
			publicKeyObject = key;
		}
		catch (const crypt::Exception &e) {
			continue;
		}

		// Get private key for Certificate
		Scoped<Object> privateKeyObject;
		if (x509->HasPrivateKey()) {
			fprintf(stdout, "Certificate '%s' has private key\n", x509->GetLabel()->c_str());
			try {
				Scoped<crypt::Key> privateKey = x509->GetPrivateKey();
				Scoped<MscapiRsaPrivateKey> key(new MscapiRsaPrivateKey(privateKey, true));
				key->id = *x509->GetHashPublicKey().get();
				privateKeyObject = key;
			}
			catch (crypt::Exception &e) {
				// If we cannot get private key for certificate, we don't have to show this certificate in list
				continue;
			}
		}

		this->objects.add(x509Object);
		this->objects.add(publicKeyObject);
		this->objects.add(privateKeyObject);
	}
}

CK_RV MscapiSession::OpenSession
(
	CK_FLAGS              flags,         /* from CK_SESSION_INFO */
	CK_VOID_PTR           pApplication,  /* passed to callback */
	CK_NOTIFY             Notify,        /* callback function */
	CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
	// TestPrintContainers(PROV_RSA_AES);
	// TestCipher();

	CK_RV res = Session::OpenSession(flags, pApplication, Notify, phSession);

	if (!CryptAcquireContext(&hRsaAesProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		printf("Acquisition of context failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (res == CKR_OK) {
		LoadMyStore();
	}
	return res;
}

CK_RV MscapiSession::CloseSession()
{
	CK_RV res = Session::CloseSession();

	this->objects.clear();

	// close all opened stores
	for (size_t i = 0; i < this->certStores.count(); i++) {
		this->certStores.items(i)->Close();
	}

	if (hRsaAesProv) {
		CryptReleaseContext(hRsaAesProv, 0);
		hRsaAesProv = NULL;
	}

	return res;
}

CK_RV MscapiSession::FindObjectsInit
(
	CK_ATTRIBUTE_PTR  pTemplate,  /* attribute values to match */
	CK_ULONG          ulCount     /* attributes in search template */
)
{
	CK_RV res = Session::FindObjectsInit(pTemplate, ulCount);
	if (res != CKR_OK) {
		return res;
	}

	return CKR_OK;
}

CK_RV MscapiSession::FindObjects
(
	CK_OBJECT_HANDLE_PTR phObject,          /* gets obj. handles */
	CK_ULONG             ulMaxObjectCount,  /* max handles to get */
	CK_ULONG_PTR         pulObjectCount     /* actual # returned */
)
{
	CK_RV res = Session::FindObjects(phObject, ulMaxObjectCount, pulObjectCount);
	if (res != CKR_OK) {
		return res;
	}

	for (this->find.index; this->find.index < this->objects.count() && *pulObjectCount < ulMaxObjectCount; this->find.index++) {
		Scoped<Object> obj = this->objects.items(this->find.index);
		size_t i = 0;
		for (i; i < this->find.ulTemplateSize; i++) {
			CK_ATTRIBUTE_PTR findAttr = &this->find.pTemplate[i];
			CK_BYTE_PTR pbAttrValue = NULL;
			CK_ATTRIBUTE attr = { findAttr->type , NULL_PTR, 0 };
			res = obj->GetAttributeValue(&attr, 1);
			if (res != CKR_OK) {
				break;
			}
			if (attr.ulValueLen != findAttr->ulValueLen) {
				break;
			}
			pbAttrValue = (CK_BYTE_PTR)malloc(attr.ulValueLen);
			attr.pValue = pbAttrValue;
			res = obj->GetAttributeValue(&attr, 1);
			if (res != CKR_OK) {
				free(pbAttrValue);
				break;
			}
			if (memcmp(findAttr->pValue, attr.pValue, findAttr->ulValueLen)) {
				free(pbAttrValue);
				break;
			}
			free(pbAttrValue);
		}
		if (i != this->find.ulTemplateSize) {
			continue;
		}

		phObject[*pulObjectCount] = obj->handle;
		*pulObjectCount += 1;
	}

	return CKR_OK;
}

CK_RV MscapiSession::FindObjectsFinal()
{
	CK_RV res = Session::FindObjectsFinal();
	if (res != CKR_OK) {
		return res;
	}

	return CKR_OK;
}

CK_RV MscapiSession::DigestInit
(
	CK_MECHANISM_PTR  pMechanism  /* the digesting mechanism */
)
{
	CK_RV res = Session::DigestInit(pMechanism);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}

	// get algorithm
	ALG_ID algID;
	switch (pMechanism->mechanism) {
	case CKM_SHA_1:
		algID = CALG_SHA1;
		break;
	case CKM_SHA256:
		algID = CALG_SHA_256;
		break;
	case CKM_SHA384:
		algID = CALG_SHA_384;
		break;
	case CKM_SHA512:
		algID = CALG_SHA_512;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	Scoped<crypt::Provider> prov = crypt::Provider::Create(NULL, NULL, PROV_RSA_AES, 0);
	hash = crypt::Hash::Create(prov, algID, NULL, 0);

	this->digestInitialized = true;

	return CKR_OK;
}

CK_RV MscapiSession::DigestUpdate
(
	CK_BYTE_PTR       pPart,     /* data to be digested */
	CK_ULONG          ulPartLen  /* bytes of data to be digested */
)
{
	CK_RV res = Session::DigestUpdate(pPart, ulPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}

	hash->Update(pPart, ulPartLen);

	return CKR_OK;
}

CK_RV MscapiSession::DigestKey
(
	CK_OBJECT_HANDLE  hKey       /* secret key to digest */
)
{
	return Session::DigestKey(hKey);
}

CK_RV MscapiSession::DigestFinal
(
	CK_BYTE_PTR       pDigest,      /* gets the message digest */
	CK_ULONG_PTR      pulDigestLen  /* gets byte count of digest */
)
{
	CK_RV res = Session::DigestFinal(pDigest, pulDigestLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}

	// compare incoming data size with output data size
	if (*pulDigestLen < hash->GetSize()) {
		return CKR_BUFFER_TOO_SMALL;
	}

	// digest
	Scoped<std::string> digest = hash->GetValue();
	memcpy(pDigest, digest->c_str(), digest->length());
	*pulDigestLen = digest->length();
	this->digestInitialized = false;

	return CKR_OK;
}

CK_RV MscapiSession::VerifyInit(
	CK_MECHANISM_PTR  pMechanism,  /* the verification mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	CK_RV res = Session::VerifyInit(pMechanism, hKey);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// get key
	Scoped<Object> object = this->GetObject(hKey);
	DWORD dwProvType;
	ALG_ID algID;
	MscapiRsaPublicKey* rsaKey;
	if (rsaKey = dynamic_cast<MscapiRsaPublicKey*>(object.get())) {
		dwProvType = PROV_RSA_AES;
		switch (pMechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
			algID = CALG_SHA1;
			break;
		case CKM_SHA256_RSA_PKCS:
			algID = CALG_SHA_256;
			break;
		case CKM_SHA384_RSA_PKCS:
			algID = CALG_SHA_384;
			break;
		case CKM_SHA512_RSA_PKCS:
			algID = CALG_SHA_512;
			break;
		default:
			puts("MscapiSession::VerifyInit:RSA switch hash algorithm");
			return CKR_MECHANISM_INVALID;
		}
	}
	else {
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	this->verify = crypt::Verify::Create(algID, rsaKey->value);
	this->verifyInitialized = true;

	return CKR_OK;
}

CK_RV MscapiSession::VerifyUpdate(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	CK_RV res = Session::VerifyUpdate(pPart, ulPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// Update
	verify->Update(pPart, ulPartLen);

	return res;
}

CK_RV MscapiSession::VerifyFinal(
	CK_BYTE_PTR       pSignature,     /* signature to verify */
	CK_ULONG          ulSignatureLen  /* signature length */
)
{
	CK_RV res = Session::VerifyFinal(pSignature, ulSignatureLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// Update
	if (!verify->Final(pSignature, ulSignatureLen)) {
		return CKR_SIGNATURE_INVALID;
	}

	return res;
}

CK_RV MscapiSession::SignInit(
	CK_MECHANISM_PTR  pMechanism,  /* the signing mechanism */
	CK_OBJECT_HANDLE  hKey         /* verification key */
)
{
	CK_RV res = Session::SignInit(pMechanism, hKey);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// get key
	Scoped<Object> object = this->GetObject(hKey);
	HCRYPTKEY hSignKey;
	DWORD dwProvType;
	ALG_ID algID;
	MscapiRsaPrivateKey* rsaKey;
	if (rsaKey = dynamic_cast<MscapiRsaPrivateKey*>(object.get())) {
		hSignKey = rsaKey->value->Get();
		dwProvType = PROV_RSA_AES;
		switch (pMechanism->mechanism) {
		case CKM_SHA1_RSA_PKCS:
			algID = CALG_SHA1;
			break;
		case CKM_SHA256_RSA_PKCS:
			algID = CALG_SHA_256;
			break;
		case CKM_SHA384_RSA_PKCS:
			algID = CALG_SHA_384;
			break;
		case CKM_SHA512_RSA_PKCS:
			algID = CALG_SHA_512;
			break;
		default:
			puts("MscapiSession::SignInit:RSA switch hash algorithm");
			return CKR_MECHANISM_INVALID;
		}
	}
	else {
		return CKR_KEY_TYPE_INCONSISTENT;
	}

	this->sign = crypt::Sign::Create(algID, rsaKey->value);
	this->signInitialized = true;

	return CKR_OK;
}

CK_RV MscapiSession::SignUpdate(
	CK_BYTE_PTR       pPart,     /* signed data */
	CK_ULONG          ulPartLen  /* length of signed data */
)
{
	CK_RV res = Session::SignUpdate(pPart, ulPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// Update
	this->sign->Update(pPart, ulPartLen);

	return res;
}

CK_RV MscapiSession::SignFinal(
	CK_BYTE_PTR       pSignature,      /* signature */
	CK_ULONG_PTR      pulSignatureLen  /* signature length */
)
{
	CK_RV res = Session::SignFinal(pSignature, pulSignatureLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	// Update
	Scoped<std::string> signature = this->sign->Final();
	this->signInitialized = false;

	memcpy(pSignature, signature->c_str(), signature->length());
	*pulSignatureLen = signature->length();

	return res;
}

Scoped<Object> MscapiSession::GetObject(CK_OBJECT_HANDLE hObject)
{
	for (size_t i = 0; i < this->objects.count(); i++) {
		Scoped<Object> object = this->objects.items(i);

		if (object->handle == hObject) {
			return object;
		}
	}
	return NULL;
}

CK_BBOOL MscapiSession::TEMPLATES_EQUALS(CK_ATTRIBUTE_PTR pTemplate1, CK_ULONG ulTemplate1Size, CK_ATTRIBUTE_PTR pTemplate2, CK_ULONG ulTemplate2Size)
{
	if (ulTemplate1Size != ulTemplate2Size) {
		return false;
	}

	for (CK_ULONG i = 0; i < ulTemplate1Size; i++) {
		if (memcmp(pTemplate1[i].pValue, pTemplate2[i].pValue, ulTemplate1Size) != 0) {
			return false;
		}
	}

	return true;
}

CK_RV MscapiSession::EncryptInit
(
	CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
) 
{
	CK_RV res = Session::EncryptInit(pMechanism, hKey);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	this->encryptInitialized = true;

	return res;
}

CK_RV MscapiSession::EncryptUpdate
(
	CK_BYTE_PTR       pPart,              /* the plaintext data */
	CK_ULONG          ulPartLen,          /* plaintext data len */
	CK_BYTE_PTR       pEncryptedPart,     /* gets ciphertext */
	CK_ULONG_PTR      pulEncryptedPartLen /* gets c-text size */
)
{
	CK_RV res = Session::EncryptUpdate(pPart, ulPartLen, pEncryptedPart, pulEncryptedPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	return res;
}

CK_RV MscapiSession::EncryptFinal
(
	CK_BYTE_PTR       pLastEncryptedPart,      /* last c-text */
	CK_ULONG_PTR      pulLastEncryptedPartLen  /* gets last size */
)
{
	CK_RV res = Session::EncryptFinal(pLastEncryptedPart, pulLastEncryptedPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	this->encryptInitialized = false;

	return res;
}

CK_RV MscapiSession::DecryptInit
(
	CK_MECHANISM_PTR  pMechanism,  /* the decryption mechanism */
	CK_OBJECT_HANDLE  hKey         /* handle of decryption key */
)
{
	CK_RV res = Session::DecryptInit(pMechanism, hKey);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	this->decryptInitialized = true;

	return res;
}

CK_RV MscapiSession::DecryptUpdate
(
	CK_BYTE_PTR       pEncryptedPart,      /* encrypted data */
	CK_ULONG          ulEncryptedPartLen,  /* input length */
	CK_BYTE_PTR       pPart,               /* gets plaintext */
	CK_ULONG_PTR      pulPartLen           /* p-text size */
)
{
	CK_RV res = Session::DecryptUpdate(pEncryptedPart, ulEncryptedPartLen, pPart, pulPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	return res;
}

CK_RV MscapiSession::DecryptFinal
(
	CK_BYTE_PTR       pLastPart,      /* gets plaintext */
	CK_ULONG_PTR      pulLastPartLen  /* p-text size */
)
{
	CK_RV res = Session::DecryptFinal(pLastPart, pulLastPartLen);
	if (res != CKR_FUNCTION_NOT_SUPPORTED) {
		return res;
	}
	res = CKR_OK;

	this->decryptInitialized = false;

	return res;
}