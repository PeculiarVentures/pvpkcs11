#pragma once

#include "../stdafx.h"
#include "../core/collection.h"
#include "certificate.h"

#define STORE_MY L"My"
#define STORE_ADDRESS L"Address"
#define STORE_CA L"CA"
#define STORE_ROOT L"Root"

class MscapiCertStore
{
public:
	DWORD error;

	MscapiCertStore();
	~MscapiCertStore();

	Scoped<Collection<Scoped<Object>>> GetCertificates();

	CK_RV Open(LPWSTR storeName);
	CK_RV Close();
protected:
	bool opened;
	HCERTSTORE hStore;
	LPWSTR name;
};


