#pragma once

#include "secret_key.h"

namespace core {

	class AesKey : public SecretKey {

	public:
		AesKey();

		CK_RV GetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
			CK_ULONG          ulCount     /* attributes in template */
		);

		virtual DECLARE_GET_ATTRIBUTE(GetValue);
		virtual DECLARE_GET_ATTRIBUTE(GetValueLen);

	protected:
		CK_ULONG            propValueLen;
        Scoped<std::string> propValue;

	};

}
