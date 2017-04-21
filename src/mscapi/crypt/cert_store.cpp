#include "crypt.h"

using namespace crypt;

CertStore::CertStore()
{
	this->hStore = NULL;
}

CertStore::~CertStore()
{
	this->Close();
}

void CertStore::Open(LPCSTR storeName)
{
	this->hStore = CertOpenSystemStoreA((HCRYPTPROV)NULL, storeName);
	if (this->hStore == NULL_PTR) {
		THROW_MS_ERROR();
	}
	this->name = storeName;
	this->opened = true;
}

void CertStore::Close()
{
	if (this->hStore) {
		CertCloseStore(this->hStore, 0);
		this->hStore = NULL;
	}
}

Scoped<Collection<Scoped<X509Certificate>>> CertStore::GetCertificates() {
	Scoped<Collection<Scoped<X509Certificate>>> certs(new Collection<Scoped<X509Certificate>>());
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
			Scoped<crypt::X509Certificate> x509(new crypt::X509Certificate(hCopy));
			certs->add(x509);
		}
	}
	return certs;
}