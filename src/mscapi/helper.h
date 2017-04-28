#pragma once

#include "../stdafx.h";

std::string GetLastErrorAsString();

#define PRINT_WIN_ERROR()                                 \
	fprintf(stdout, "Error: %s\n", GetLastErrorAsString().c_str())

std::string GetNTErrorAsString(NTSTATUS status);