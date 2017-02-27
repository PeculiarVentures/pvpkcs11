#pragma once

#include "../stdafx.h"
#include "../core/objects/x509_certificate.h"

class MscapiCertificate : public X509Certificate
{
public:

	CK_BBOOL trusted;

	MscapiCertificate(PCCERT_CONTEXT cert);
	MscapiCertificate(PCCERT_CONTEXT cert, CK_BBOOL trusted);
	~MscapiCertificate();

	// storage
	DECLARE_GET_ATTRIBUTE(GetToken);
	// DECLARE_GET_ATTRIBUTE(GetPrivate);
	DECLARE_GET_ATTRIBUTE(GetModifiable);
	DECLARE_GET_ATTRIBUTE(GetLabel);
	// DECLARE_GET_ATTRIBUTE(GetCopyable);
	// cert
	DECLARE_GET_ATTRIBUTE(GetTrusted);
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

protected:
	PCCERT_CONTEXT cert;
};

