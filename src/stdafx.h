#pragma once

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN

#include <stdio.h>
#include <tchar.h>
#include <windows.h>
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

/**
 * Set padded string for PKCS#11 structures
 */
void SET_STRING(CK_UTF8CHAR* storage, char* data, int size);

// check incoming argument, if argument is NULL returns CKR_ARGUMENTS_BAD
#define CHECK_ARGUMENT_NULL(name)				\
	if (name == NULL_PTR) {						\
		return CKR_ARGUMENTS_BAD;				\
	}
