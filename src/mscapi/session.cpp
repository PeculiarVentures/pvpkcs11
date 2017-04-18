#include "../stdafx.h"
#include "helper.h"
#include "session.h"
#include "key.h"
#include "rsa_public_key.h"
#include "rsa_private_key.h"

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
	if (this->hHash) {
		CryptDestroyHash(this->hHash);
		this->hHash = NULL;
	}
}

void MscapiSession::LoadStore(LPWSTR storeName)
{
	Scoped<MscapiCertStore> store(new MscapiCertStore());
	this->certStores.add(store);
	store->Open(storeName);
	Scoped<Collection<Scoped<Object>>> certs = store->GetCertificates();

	for (size_t i = 0; i < certs->count(); i++) {
		Scoped<Object> item = certs->items(i);
		if (MscapiCertificate* cert = dynamic_cast<MscapiCertificate*>(item.get())) {
			Scoped<Object>publicKey = this->GetPublicKey(cert);
			if (publicKey.get()) {
				try {
					Scoped<Object> privateKey = GetPrivateKey(cert);
					this->objects.add(privateKey);
				}
				catch (...) {

				}
				this->objects.add(publicKey);
				this->objects.add(item);
			}
		}
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
	CK_RV res = Session::OpenSession(flags, pApplication, Notify, phSession);

	if (!CryptAcquireContext(&hRsaAesProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
		printf("Acquisition of context failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (res == CKR_OK) {
		LoadStore(STORE_MY);
		// LoadStore(STORE_ADDRESS);
		// LoadStore(STORE_CA);
		// LoadStore(STORE_ROOT);
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
		dwHashLength = 20;
		break;
	case CKM_SHA256:
		algID = CALG_SHA_256;
		dwHashLength = 32;
		break;
	case CKM_SHA384:
		algID = CALG_SHA_384;
		dwHashLength = 48;
		break;
	case CKM_SHA512:
		algID = CALG_SHA_512;
		dwHashLength = 64;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}

	if (!CryptCreateHash(hRsaAesProv, algID, 0, 0, &hHash)) {
		printf("Error during CryptBeginHash!\n");
		return CKR_FUNCTION_FAILED;
	}

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

	if (!CryptHashData(hHash, (BYTE*)pPart, (DWORD)ulPartLen, 0)) {
		printf("Error during CryptHashData.\n");
		return CKR_FUNCTION_FAILED;
	}

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
	res = CKR_OK;

	// compare incoming data size with output data size
	if (res == CKR_OK && *pulDigestLen < dwHashLength) {
		res = CKR_BUFFER_TOO_SMALL;
	}

	// digest
	if (res == CKR_OK && !CryptGetHashParam(hHash, HP_HASHVAL, pDigest, pulDigestLen, 0)) {
		puts("Cannot get hash");
		res = CKR_FUNCTION_FAILED;
	}

	// close handles
	if (hHash)
		CryptDestroyHash(hHash);

	this->digestInitialized = false;

	return res;
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
	HCRYPTKEY hVerifyKey;
	DWORD dwProvType;
	ALG_ID algID;
	MscapiRsaPublicKey* rsaKey;
	if (rsaKey = dynamic_cast<MscapiRsaPublicKey*>(object.get())) {
		hVerifyKey = rsaKey->key->handle;
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

	this->verify = CryptoVerify();
	res = this->verify.Init(this->hRsaAesProv, algID, hVerifyKey);
	if (res == CKR_OK) {
		this->verifyInitialized = true;
	}

	return res;
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
	res = this->verify.Update(pPart, ulPartLen);

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
	res = this->verify.Final(pSignature, ulSignatureLen);

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
		hSignKey = rsaKey->hKey;
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

	this->sign = CryptoSign();
	res = this->sign.Init(rsaKey->hProv, algID, rsaKey->hKey);
	if (res == CKR_OK) {
		this->signInitialized = true;
	}

	return res;
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
	res = this->sign.Update(pPart, ulPartLen);

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
	res = this->sign.Final(pSignature, pulSignatureLen);
	this->signInitialized = false;
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

Scoped<Object> MscapiSession::GetPublicKey(MscapiCertificate* cert)
{
	// TODO: Get dwKeySpec from Certificate's KeyUsages
	HCRYPTKEY hPublicKey;
	if (CryptImportPublicKeyInfo(
		hRsaAesProv,
		X509_ASN_ENCODING,
		&cert->cert->pCertInfo->SubjectPublicKeyInfo,
		&hPublicKey
	))
	{
		// check key algorithm
		DWORD dwDataLen;
		ALG_ID algId;
		// puts("CryptGetKeyParam");
		if (CryptGetKeyParam(hPublicKey, KP_ALGID, (BYTE*)&algId, &dwDataLen, 0)) {
			if (GET_ALG_TYPE(algId) == ALG_TYPE_RSA) {
				Scoped<MscapiKey> key(new MscapiKey());
				key->handle = hPublicKey;
				Scoped<MscapiRsaPublicKey> object(new MscapiRsaPublicKey());
				object->key = key;
				object->token = CK_TRUE;
				CK_BYTE_PTR bId = NULL;
				CK_ULONG ulId = 0;
				if (CKR_OK != cert->GetID(bId, &ulId)) {
					return NULL;
				}
				bId = (CK_BYTE_PTR)malloc(ulId);
				if (CKR_OK != cert->GetID(bId, &ulId)) {
					free(bId);
					return NULL;
				}
				object->id.append((char*)bId, ulId);
				free(bId);

				return object;
			}
		}
		return NULL;
	}

	return NULL;
}

Scoped<Object> MscapiSession::GetPrivateKey(MscapiCertificate* cert)
{
	// TODO: Get dwKeySpec from Certificate's KeyUsages
	HCRYPTKEY hPrivateKey;
	HCRYPTPROV hPrivateKeyProv;
	DWORD dwKeySpec;
	if (!CryptAcquireCertificatePrivateKey(cert->cert, CRYPT_ACQUIRE_SILENT_FLAG, NULL, &hPrivateKeyProv, &dwKeySpec, NULL)) {
		puts("MscapiSession::GetPrivateKey:CryptAcquireCertificatePrivateKey: Cannot acquire provider for certificate");
		PRINT_WIN_ERROR();
		throw CKR_FUNCTION_FAILED;
	}

	if (!CryptGetUserKey(hPrivateKeyProv, dwKeySpec, &hPrivateKey)) {
		puts("MscapiSession::GetPrivateKey:CryptGetUserKey: Cannot get private key for certificate");
		PRINT_WIN_ERROR();
		throw CKR_FUNCTION_FAILED;
	}
	Scoped<MscapiRsaPrivateKey> mscapiKey(new MscapiRsaPrivateKey(hPrivateKeyProv, hPrivateKey));
	CK_ULONG ulId = 0;
	if (CKR_OK != cert->GetID(NULL, &ulId)) {
		puts("MscapiSession::GetPrivateKey: Cannot get ID from Certificate");
		throw CKR_FUNCTION_FAILED;
	}
	mscapiKey->id.resize(ulId);
	if (CKR_OK != cert->GetID((CK_BYTE_PTR)mscapiKey->id.c_str(), &ulId)) {
		puts("MscapiSession::GetPrivateKey: Cannot get ID from Certificate");
		return NULL;
	}

	return mscapiKey;
}
