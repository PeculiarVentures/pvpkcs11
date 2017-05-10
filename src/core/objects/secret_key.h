#pragma once

#include "../../stdafx.h"
#include "key.h"

namespace core {

	class SecretKey : public Key {

	public:
		CK_RV GetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
			CK_ULONG          ulCount     /* attributes in template */
		);

		DECLARE_GET_ATTRIBUTE(GetClass);

		virtual DECLARE_GET_ATTRIBUTE(GetSensitive);
		virtual DECLARE_GET_ATTRIBUTE(GetEncrypt);
		virtual DECLARE_GET_ATTRIBUTE(GetDecrypt);
		virtual DECLARE_GET_ATTRIBUTE(GetSign);
		virtual DECLARE_GET_ATTRIBUTE(GetVerify);
		virtual DECLARE_GET_ATTRIBUTE(GetWrap);
		virtual DECLARE_GET_ATTRIBUTE(GetUnwrap);
		virtual DECLARE_GET_ATTRIBUTE(GetExtractable);
		virtual DECLARE_GET_ATTRIBUTE(GetAlwaysSensitive);
		virtual DECLARE_GET_ATTRIBUTE(GetNeverExtractable);
		virtual DECLARE_GET_ATTRIBUTE(GetCheckValue);
		virtual DECLARE_GET_ATTRIBUTE(GetWrapWithTrusted);
		virtual DECLARE_GET_ATTRIBUTE(GetTrusted);
		virtual DECLARE_GET_ATTRIBUTE(GetWrapTemplate);
		virtual DECLARE_GET_ATTRIBUTE(GetUnwrapTemplate);

	protected:
		CK_BBOOL    propSensitive;
		CK_BBOOL    propEncrypt;
		CK_BBOOL    propDecrypt;
		CK_BBOOL    propSign;
		CK_BBOOL    propVerify;
		CK_BBOOL    propWrap;
		CK_BBOOL    propUnwrap;
		CK_BBOOL    propExtractable;
		CK_BBOOL    propAlwaysSensitive;
		CK_BBOOL    propNeverExtractable;
		std::string propCheckValue;
		CK_BBOOL    propWrapWithTrusted;
		CK_BBOOL    propTrusted;
	};

}
