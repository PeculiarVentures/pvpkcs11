#include "cert_store.h"

MscapiCertStore::MscapiCertStore()
{
	this->hStore = NULL;
}

MscapiCertStore::~MscapiCertStore()
{
	this->Close();
}

CK_RV MscapiCertStore::Open(LPWSTR storeName)
{
	this->hStore = CertOpenSystemStore((HCRYPTPROV)NULL, storeName);
	if (this->hStore == NULL_PTR) {
		this->error = GetLastError();
		return CKR_FUNCTION_FAILED;
	}
	this->error = 0;
	this->name = storeName;
	this->opened = true;

	return CKR_OK;
}

CK_RV MscapiCertStore::Close()
{
	if (this->hStore) {
		CertCloseStore(this->hStore, 0);
		this->hStore = NULL;
	}
	return CKR_OK;
}

Scoped<Collection<Scoped<Object>>> MscapiCertStore::GetCertificates() {
	Scoped<Collection<Scoped<Object>>> certs(new Collection<Scoped<Object>>());
	// get certificates
	PCCERT_CONTEXT hCert = NULL;
	while (true)
	{
		hCert = CertEnumCertificatesInStore(
			this->hStore,
			hCert
		);
		if (hCert == NULL) {
			break;
		}
		else {
			PCCERT_CONTEXT hCopy = CertDuplicateCertificateContext(hCert);
			Scoped<Object> cert(new MscapiCertificate(hCopy, lstrcmp(this->name, STORE_ROOT) == 0));
			certs->add(cert);
		}
	}
	return certs;
}