#pragma once

#include <Winscard.h>

#include "helper.h"

namespace scard {

    class Card {
    public:
        Scoped<std::string> name;

        Card(Scoped<SCARDCONTEXT> context, Scoped<std::string> name);

        BOOL HasProviderName(
            DWORD        dwProviderId
        );
        Scoped<std::string> GetProviderName(
            DWORD        dwProviderId
        );
    protected:
        Scoped<SCARDCONTEXT> context;
    };

    class Reader {
    public:
        Scoped<std::string>     name;

        Reader(
            Scoped<SCARDCONTEXT>    context,
            Scoped<std::string>     name
        );
        ~Reader();

        void Connect(
            DWORD dwShareMode,
            DWORD dwPreferredProtocols
        );

        void Disconnect(DWORD flag = SCARD_LEAVE_CARD);

        BOOL HasProviderName(
            DWORD        dwProviderId
        );

        Scoped<std::string> GetProviderName(
            DWORD        dwProviderId
        );

        Scoped<Buffer> GetAttributeBytes(
            DWORD attrId
        );
        Scoped<std::string> GetAttributeString(
            DWORD attrId
        );

    protected:
        Scoped<SCARDCONTEXT>    context;
        SCARDHANDLE             handle;
        DWORD                   activateProtocol;
    };

    class Context {
    public:
        Context();
        ~Context();

        void Initialize(
            DWORD dwScope
        );

        List<Scoped<Reader>> GetReaders();
        List<Scoped<Card>> GetCards(
            Scoped<Buffer> atr
        );
    protected:
        Scoped<SCARDCONTEXT> context;
    };

#define SCARD_EXCEPTION_NAME "SCardException"

#define THROW_SCARD_EXCEPTION(code, fn)     \
	THROW_MSCAPI_CODE_ERROR(SCARD_EXCEPTION_NAME, fn, code)

}
