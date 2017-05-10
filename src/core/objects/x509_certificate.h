#pragma once

#include "certificate.h"

namespace core {

	class X509Certificate : public Certificate
	{
	public:
		X509Certificate();
		~X509Certificate();

		CK_RV GetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
			CK_ULONG          ulCount     /* attributes in template */
		);
		CK_RV SetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes and values */
			CK_ULONG          ulCount     /* attributes in template */
		);

		DECLARE_GET_ATTRIBUTE(GetCertificateType);
		virtual DECLARE_GET_ATTRIBUTE(GetSubject);
		virtual DECLARE_GET_ATTRIBUTE(GetID);
		virtual DECLARE_GET_ATTRIBUTE(GetIssuer);
		virtual DECLARE_GET_ATTRIBUTE(GetSerialNumber);
		virtual DECLARE_GET_ATTRIBUTE(GetValue);
		virtual DECLARE_GET_ATTRIBUTE(GetURL);
		virtual DECLARE_GET_ATTRIBUTE(GetHashOfSubjectPublicKey);
		virtual DECLARE_GET_ATTRIBUTE(GetHashOfIssuerPublicKey);
		virtual DECLARE_GET_ATTRIBUTE(GetJavaMidpSecurityDomain);
		virtual DECLARE_GET_ATTRIBUTE(GetNameHashAlgorithm);

	};

}
