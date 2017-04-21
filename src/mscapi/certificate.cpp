#include "certificate.h"

MscapiCertificate::MscapiCertificate(Scoped<crypt::X509Certificate> value, CK_BBOOL token) 
{
	this->handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
	this->value = value;
	this->token = token;
}

MscapiCertificate::~MscapiCertificate()
{
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetLabel)
{
	Scoped<std::string> buf = this->value->GetLabel();
	return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)buf->c_str(), buf->length());
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSerialNumber)
{
	return this->GetBytes(
		pValue, pulValueLen,
		this->value->Get()->pCertInfo->SerialNumber.pbData,
		this->value->Get()->pCertInfo->SerialNumber.cbData
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetValue)
{
	return this->GetBytes(
		pValue, pulValueLen,
		this->value->Get()->pbCertEncoded,
		this->value->Get()->cbCertEncoded
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSubject)
{
	return this->GetBytes(
		pValue, pulValueLen, 
		this->value->Get()->pCertInfo->Subject.pbData, 
		this->value->Get()->pCertInfo->Subject.cbData
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetIssuer)
{
	return this->GetBytes(
		pValue, pulValueLen, 
		this->value->Get()->pCertInfo->Issuer.pbData, 
		this->value->Get()->pCertInfo->Issuer.cbData
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetTrusted)
{
	return this->GetBool(pValue, pulValueLen, this->trusted);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetCertificateCategory)
{
	// Categorization of the certificate : 0 = unspecified(default value), 1 = token user, 2 = authority, 3 = other entity.
	return this->GetNumber(pValue, pulValueLen, 0);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetCheckValue)
{
	CK_BYTE buf[64];
	CK_ULONG bufLen;
	if (!CertGetCertificateContextProperty(this->value->Get(), CERT_HASH_PROP_ID, buf, &bufLen)) {
		return CKR_FUNCTION_FAILED;
	}
	if (pValue) {
		return this->GetBytes(pValue, pulValueLen, buf, CERTIFICATE_CHECK_VALUE_LENGTH);
	}
	*pulValueLen = CERTIFICATE_CHECK_VALUE_LENGTH;
	return CKR_OK;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetID)
{
	Scoped<std::string> hash = this->value->GetHashPublicKey();
	return this->GetBytes(
		pValue, pulValueLen,
		(BYTE*)hash->c_str(),
		hash->length()
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfSubjectPublicKey)
{
	Scoped<std::string> hash = this->value->GetHashPublicKey();
	return this->GetBytes(
		pValue, pulValueLen, 
		(BYTE*)hash->c_str(),
		CERTIFICATE_CHECK_VALUE_LENGTH
	);
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfIssuerPublicKey)
{
	return this->GetBytes(pValue, pulValueLen, NULL, 0);
}


