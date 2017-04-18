#pragma once

#include "../stdafx.h"

class MscapiKey {

public:
	static Scoped<MscapiKey > Generate(HCRYPTPROV hProv, ALG_ID uiAlgId, DWORD dwFlags);
	static Scoped<MscapiKey > Import(
		_In_                    HCRYPTPROV  hProv,
		_In_reads_bytes_(dwDataLen)  CONST BYTE  *pbData,
		_In_                    DWORD       dwDataLen,
		_In_                    DWORD       dwFlags
	);

	Scoped<MscapiKey > Copy();
	void Destroy();

	HCRYPTKEY handle;

};