#pragma once

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>
#include <crtdbg.h>

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include <stdio.h>
#include <tchar.h>
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <wincrypt.h>

#endif // _WIN32

#pragma pack(push, cryptoki, 1)
#include "./pkcs11.h"
#pragma pack(pop, cryptoki)

#include <stdio.h>
#include <memory>
#include <vector>
#include <string>

template <typename T>
using Scoped = std::shared_ptr<T>;
using Buffer = std::vector<CK_BYTE>;

/**
 * Set padded string for PKCS#11 structures
 */
void SET_STRING(CK_UTF8CHAR* storage, char* data, int size);

// check incoming argument, if argument is NULL returns CKR_ARGUMENTS_BAD
#define CHECK_ARGUMENT_NULL(name)				\
	if (name == NULL_PTR) {						\
		return CKR_ARGUMENTS_BAD;				\
	}

#define CKA_X509_CHAIN (CKA_VENDOR_DEFINED|0x00000101)