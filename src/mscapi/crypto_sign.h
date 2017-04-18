#pragma once

#pragma once

#include "../stdafx.h"

class CryptoSign {

public:
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY  hKey;

	CryptoSign();
	~CryptoSign();

	CK_RV Init(
		HCRYPTPROV       prov,
		ALG_ID           algID,            /* the signing mechanism */
		HCRYPTKEY        hKey              /* signing key */
	);

	CK_RV Update(
		CK_BYTE_PTR       pPart,     /* signed data */
		CK_ULONG          ulPartLen  /* length of signed data */
	);

	CK_RV Final(
		CK_BYTE_PTR       pSignature,      /* gets the signature */
		CK_ULONG_PTR      pulSignatureLen  /* gets the signature length */
	);

};