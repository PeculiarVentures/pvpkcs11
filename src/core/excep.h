#pragma once

#include "../stdafx.h"

namespace core {

	class Exception : public std::exception {
	public:
		std::string        name;
		std::string        message;
		std::string        function;
		std::string        file;
		int                line;
		std::string        data;
		Scoped<Exception>  stack;

		Exception(
			const char*        name,
			const char*        message,
			const char*        function,
			const char*        file,
			int                line
		);

		virtual char const* what();
		void push(
			Scoped<Exception> item
		);
	};

	class Pkcs11Exception : public Exception {
	public:
		CK_RV code;
		
		Pkcs11Exception(
			const char*        name,
			int                code,
			const char*        message,
			const char*        function,
			const char*        file,
			int                line
		);
	};

}

#define EXCEPTION_NAME "Exception"

#define THROW_EXCEPTION(message)                                  \
	throw Scoped<core::Exception>(new core::Exception(EXCEPTION_NAME, message, __FUNCTION__, __FILE__, __LINE__))

#define PKCS11_EXCEPTION_NAME "Pkcs11Exception"

#define THROW_PKCS11_EXCEPTION(code, message)                     \
	throw Scoped<core::Exception>(new core::Pkcs11Exception(PKCS11_EXCEPTION_NAME, code, message, __FUNCTION__, __FILE__, __LINE__))

#define THROW_PKCS11_FUNCTION_NOT_SUPPORTED() THROW_PKCS11_EXCEPTION(CKR_FUNCTION_NOT_SUPPORTED, "Function is not supported");
#define THROW_PKCS11_ATTRIBUTE_TYPE_INVALID() THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_TYPE_INVALID, "Attribute type invalid");
#define THROW_PKCS11_TEMPLATE_INCOMPLITE() THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCOMPLETE, "Template is incomplete")
#define THROW_PKCS11_TEMPLATE_INCONSISTENT() THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCONSISTENT, "Template is inconsistent")

#define CATCH_EXCEPTION                                                 \
	catch (Scoped<core::Exception> e) {                                 \
		Scoped<core::Exception> err(new core::Exception(EXCEPTION_NAME, "Unexpected error", __FUNCTION__, __FILE__, __LINE__)); \
        e->push(err);                                                   \
        throw e;                                                        \
    }                                                                   \
    catch(...) {                                                        \
        THROW_EXCEPTION("Unexpected exception");                        \
    }