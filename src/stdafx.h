#pragma once

#define _CRTDBG_MAP_ALLOC
#include <stdlib.h>

#ifdef _WIN32

#define WIN32_LEAN_AND_MEAN
#define CERT_CHAIN_PARA_HAS_EXTRA_FIELDS

#include <tchar.h>
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <WTypesbase.h>
#include <wincrypt.h>

#endif // _WIN32

#ifdef _WIN32
#pragma pack(push, cryptoki, 1)
#endif // _WIN32

#include "./pkcs11.h"

#ifdef _WIN32
#pragma pack(pop, cryptoki)
#endif // _WIN32

#include <stdio.h>
#include <memory>
#include <vector>
#include <string>

#include "logger.h"

template <typename T>
using Scoped = std::shared_ptr<T>;
using Buffer = std::vector<CK_BYTE>;
template <typename T>
using List = std::vector<T>;
template <typename T>
using SList = std::vector<Scoped<T> >;

/**
 * Set padded string for PKCS#11 structures
 */
void SET_STRING(CK_UTF8CHAR* storage, const char* data, int size);

// check incoming argument, if argument is NULL returns CKR_ARGUMENTS_BAD
#define CHECK_ARGUMENT_NULL(name)				\
	if (name == NULL_PTR) {						\
		return CKR_ARGUMENTS_BAD;				\
	}

#define CKA_X509_CHAIN CKA_VENDOR_DEFINED | 0x00000101
#define CKA_PIN_FRIENDLY_NAME CKA_VENDOR_DEFINED | 0x00000102
#define CKA_PIN_DESCRIPTION CKA_VENDOR_DEFINED | 0x00000103

#define ARRAY_SIZE(a)                               \
((sizeof(a) / sizeof(*(a))) /                     \
static_cast<size_t>(!(sizeof(a) % sizeof(*(a)))))
