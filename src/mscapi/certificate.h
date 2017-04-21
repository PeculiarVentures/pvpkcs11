#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"
#include "crypt/crypt.h"

class MscapiCertificate : public X509Certificate
{
public:

	CK_BBOOL trusted;

	Scoped<crypt::X509Certificate> value;

	MscapiCertificate(Scoped<crypt::X509Certificate> value, CK_BBOOL token);
	~MscapiCertificate();

	// storage
	// DECLARE_GET_ATTRIBUTE(GetPrivate);
	DECLARE_GET_ATTRIBUTE(GetLabel);
	// DECLARE_GET_ATTRIBUTE(GetCopyable);
	// cert
	DECLARE_GET_ATTRIBUTE(GetTrusted);
	DECLARE_GET_ATTRIBUTE(GetCertificateCategory);
	DECLARE_GET_ATTRIBUTE(GetCheckValue);
	// DECLARE_GET_ATTRIBUTE(GetStartDate);
	// DECLARE_GET_ATTRIBUTE(GetEndDate);
	// x509
	DECLARE_GET_ATTRIBUTE(GetSubject);
	DECLARE_GET_ATTRIBUTE(GetID);
	DECLARE_GET_ATTRIBUTE(GetIssuer);
	DECLARE_GET_ATTRIBUTE(GetSerialNumber);
	DECLARE_GET_ATTRIBUTE(GetValue);
	// DECLARE_GET_ATTRIBUTE(GetURL);
	DECLARE_GET_ATTRIBUTE(GetHashOfSubjectPublicKey);
	DECLARE_GET_ATTRIBUTE(GetHashOfIssuerPublicKey);
	// DECLARE_GET_ATTRIBUTE(GetJavaMidpSecurityDomain);
	// DECLARE_GET_ATTRIBUTE(GetNameHashAlgorithm);

};

