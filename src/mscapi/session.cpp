#include "session.h"
#include "../stdafx.h"

MscapiSession::MscapiSession() : Session()
{
}


MscapiSession::~MscapiSession()
{
}

void MscapiSession::LoadStore(LPSTR storeName)
{
	Scoped<MscapiCertStore> store(new MscapiCertStore());
	this->certStores.add(store);
	store->Open(storeName);
	Scoped<Collection<Scoped<Object>>> certs = store->GetCertificates();

	for (size_t i = 0; i < certs->count(); i++) {
		this->objects.add(certs->items(i));
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

	if (res == CKR_OK) {
		LoadStore(STORE_MY);
		LoadStore(STORE_ADDRESS);
		LoadStore(STORE_CA);
		LoadStore(STORE_ROOT);
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

	for (this->find.index; this->find.index < this->find.index + this->objects.count() && *pulObjectCount < ulMaxObjectCount; this->find.index++) {
		Scoped<Object> obj = this->objects.items(this->find.index);

		// TODO: filter

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


	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
		printf("Acquisition of context failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (!CryptCreateHash(hCryptProv, algID, 0, 0, &hHash)) {
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
	if (hCryptProv)
		CryptReleaseContext(hCryptProv, 0);

	this->digestInitialized = false;

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