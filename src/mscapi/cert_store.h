#pragma once

#include "../stdafx.h"
#include "../core/collection.h"
#include "certificate.h"

#define STORE_MY "My"
#define STORE_ADDRESS "Address"
#define STORE_CA "CA"
#define STORE_ROOT "Root"

class MscapiCertStore
{
public:
	DWORD error;

	MscapiCertStore();
	~MscapiCertStore();

	Scoped<Collection<Scoped<Object>>> GetCertificates();

	CK_RV Open(LPSTR storeName);
	CK_RV Close();
protected:
	bool opened;
	HCERTSTORE hStore;
	LPSTR name;
};


