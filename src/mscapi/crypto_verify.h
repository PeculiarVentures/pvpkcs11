#pragma once

#include "../stdafx.h"

class CryptoVerify {

public:
	HCRYPTPROV hProv;
	HCRYPTHASH hHash;
	HCRYPTKEY  hKey;

	CryptoVerify();
	~CryptoVerify();

	CK_RV Init(
		HCRYPTPROV prov,         /* type of provider */
		ALG_ID     algID,            /* the verification mechanism */
		HCRYPTKEY  hKey              /* verification key */
	);

	CK_RV Update(
		CK_BYTE_PTR       pPart,     /* signed data */
		CK_ULONG          ulPartLen  /* length of signed data */
	);

	CK_RV Final(
		CK_BYTE_PTR       pSignature,     /* signature to verify */
		CK_ULONG          ulSignatureLen  /* signature length */
	);

};