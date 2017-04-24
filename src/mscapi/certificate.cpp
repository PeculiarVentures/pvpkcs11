#include "certificate.h"

MscapiCertificate::MscapiCertificate(Scoped<crypt::X509Certificate> value, CK_BBOOL token)
{
	this->handle = reinterpret_cast<CK_OBJECT_HANDLE>(this);
	this->value = value;
	this->propToken = token;
}

MscapiCertificate::~MscapiCertificate()
{
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetLabel)
{
	try {
		Scoped<std::string> buf = this->value->GetLabel();
		return this->GetBytes(pValue, pulValueLen, (CK_BYTE_PTR)buf->c_str(), buf->length());
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSerialNumber)
{
	try {
		return this->GetBytes(
			pValue, pulValueLen,
			this->value->Get()->pCertInfo->SerialNumber.pbData,
			this->value->Get()->pCertInfo->SerialNumber.cbData
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetValue)
{
	try {
		return this->GetBytes(
			pValue, pulValueLen,
			this->value->Get()->pbCertEncoded,
			this->value->Get()->cbCertEncoded
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetSubject)
{
	try {
		return this->GetBytes(
			pValue, pulValueLen,
			this->value->Get()->pCertInfo->Subject.pbData,
			this->value->Get()->pCertInfo->Subject.cbData
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetIssuer)
{
	try {
		return this->GetBytes(
			pValue, pulValueLen,
			this->value->Get()->pCertInfo->Issuer.pbData,
			this->value->Get()->pCertInfo->Issuer.cbData
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetTrusted)
{
	try {
		return this->GetBool(pValue, pulValueLen, this->trusted);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetCertificateCategory)
{
	try {
		// Categorization of the certificate : 0 = unspecified(default value), 1 = token user, 2 = authority, 3 = other entity.
		return this->GetNumber(pValue, pulValueLen, 0);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetCheckValue)
{
	try {
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
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetID)
{
	try {
		Scoped<std::string> hash = this->value->GetHashPublicKey();
		return this->GetBytes(
			pValue, pulValueLen,
			(BYTE*)hash->c_str(),
			hash->length()
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfSubjectPublicKey)
{
	try {
		Scoped<std::string> hash = this->value->GetHashPublicKey();
		return this->GetBytes(
			pValue, pulValueLen,
			(BYTE*)hash->c_str(),
			CERTIFICATE_CHECK_VALUE_LENGTH
		);
	}
	CATCH_EXCEPTION;
}

DECLARE_GET_ATTRIBUTE(MscapiCertificate::GetHashOfIssuerPublicKey)
{
	try {
		return this->GetBytes(pValue, pulValueLen, NULL, 0);
	}
	CATCH_EXCEPTION;
}


