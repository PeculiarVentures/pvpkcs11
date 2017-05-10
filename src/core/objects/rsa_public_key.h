#pragma once

#include "public_key.h"

namespace core {

	class RsaPublicKey : public PublicKey {

	public:
		CK_RV GetAttributeValue
		(
			CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
			CK_ULONG          ulCount     /* attributes in template */
		);

		DECLARE_GET_ATTRIBUTE(GetKeyType);

		virtual DECLARE_GET_ATTRIBUTE(GetModulus);
		virtual DECLARE_GET_ATTRIBUTE(GetModulusBits);
		virtual DECLARE_GET_ATTRIBUTE(GetPublicExponent);

	};

}
