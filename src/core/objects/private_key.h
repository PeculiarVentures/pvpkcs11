#pragma once

#include "../../stdafx.h"
#include "key.h"

namespace core {

	class PrivateKey : public Key {

	public:
		CK_RV GetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
			CK_ULONG          ulCount     /* attributes in template */
		);

		DECLARE_GET_ATTRIBUTE(GetClass);

		virtual DECLARE_GET_ATTRIBUTE(GetSubject);
		virtual DECLARE_GET_ATTRIBUTE(GetSensitive);
		virtual DECLARE_GET_ATTRIBUTE(GetDecrypt);
		virtual DECLARE_GET_ATTRIBUTE(GetSign);
		virtual DECLARE_GET_ATTRIBUTE(GetSignRecover);
		virtual DECLARE_GET_ATTRIBUTE(GetUnwrap);
		virtual DECLARE_GET_ATTRIBUTE(GetExtractable);
		virtual DECLARE_GET_ATTRIBUTE(GetAlwaysSensitive);
		virtual DECLARE_GET_ATTRIBUTE(GetNeverExtractable);
		virtual DECLARE_GET_ATTRIBUTE(GetWrapWithTrusted);
		virtual DECLARE_GET_ATTRIBUTE(GetUnwrapTemplate);
		virtual DECLARE_GET_ATTRIBUTE(GetAlwaysAuthenticate);

		std::string    propSubject;
		CK_BBOOL       propSensitive;
		CK_BBOOL       propDecrypt;
		CK_BBOOL       propSign;
		CK_BBOOL       propSignRecover;
		CK_BBOOL       propUnwrap;
		CK_BBOOL       propExtractable;
		CK_BBOOL       propAlwaysSensitive;
		CK_BBOOL       propNeverExtractable;
		CK_BBOOL       propWrapWithTrusted;
		// TODO: propUnwrapTemplate;
		CK_BBOOL       propAlwaysAuthenticate;

	};

}