#include "crypt.h"

using namespace crypt;

CertStore::CertStore()
{
	try {
		this->hStore = NULL;
	}
	CATCH_EXCEPTION;
}

CertStore::~CertStore()
{
	try {
		this->Close();
	}
	CATCH_EXCEPTION;
}

void CertStore::Open(LPCSTR storeName)
{
	try {
		this->hStore = CertOpenSystemStoreA((HCRYPTPROV)NULL, storeName);
		if (this->hStore == NULL_PTR) {
			THROW_MSCAPI_ERROR();
		}
		this->name = storeName;
		this->opened = true;
	}
	CATCH_EXCEPTION;
}

void CertStore::Close()
{
	try {
		if (this->hStore) {
			CertCloseStore(this->hStore, 0);
			this->hStore = NULL;
		}
	}
	CATCH_EXCEPTION;
}

std::vector<Scoped<mscapi::X509Certificate>> CertStore::GetCertificates() {
    std::vector<Scoped<mscapi::X509Certificate>> certs;
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
			Scoped<mscapi::X509Certificate> x509(new mscapi::X509Certificate());
            x509->Assign(hCopy);
            x509->ItemByType(CKA_TOKEN)->To<core::AttributeBool>()->Set(true);
			certs.push_back(x509);
		}
	}
	return certs;
}