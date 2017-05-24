#pragma once

#include "../stdafx.h"
#include "../core/excep.h"
#include <ntstatus.h>

std::string GetLastErrorAsString();

#define PRINT_WIN_ERROR()                                 \
	fprintf(stdout, "Error: %s\n", GetLastErrorAsString().c_str())

std::string GetNTErrorAsString(NTSTATUS status);

#define NT_EXCEPTION_NAME "NTException"

#define THROW_NT_EXCEPTION(status)                                        \
	throw Scoped<core::Exception>(new core::Pkcs11Exception(NT_EXCEPTION_NAME, CKR_FUNCTION_FAILED, GetNTErrorAsString(status).c_str(), __FUNCTION__, __FILE__, __LINE__))