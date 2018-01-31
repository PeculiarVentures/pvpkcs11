#include "scard.h"

using namespace scard;

void FreeSCardContext(LPSCARDCONTEXT hContext) {
    if (hContext) {
        SCARDCONTEXT context = *hContext;
        SCardReleaseContext(context);
        free(hContext);
    }
}

scard::Context::Context() :
    context(NULL)
{
}

scard::Context::~Context()
{
}

void scard::Context::Initialize(DWORD dwScope)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SCARDCONTEXT * hContext = (SCARDCONTEXT *)malloc(sizeof(SCARDCONTEXT));
        NTSTATUS status = SCardEstablishContext(dwScope, NULL, NULL, hContext);
        if (status != SCARD_S_SUCCESS) {
            free(hContext);
            THROW_SCARD_EXCEPTION(status, "SCardEstablishContext");
        }

        context = Scoped    <SCARDCONTEXT>(hContext, FreeSCardContext);
    }
    CATCH_EXCEPTION
}

List<Scoped<Reader>> scard::Context::GetReaders()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        List<Scoped<Reader>> res;
        SCARDCONTEXT hContext = *context.get();
        std::string readers;
        DWORD dwSize = 0;
        LPSTR pReader = NULL;

        NTSTATUS status = SCardListReaders(hContext, SCARD_ALL_READERS, NULL, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardListReaders");
        }

        readers.resize(dwSize);

        status = SCardListReaders(hContext, SCARD_ALL_READERS, (LPSTR)readers.c_str(), &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardListReaders");
        }

        pReader = (LPSTR)readers.c_str();
        while ('\0' != *pReader)
        {
            Scoped<std::string> name(new std::string(pReader));
            Scoped<Reader> reader(new Reader(context, name));
            res.push_back(reader);

            // Advance to the next value.
            pReader = pReader + strlen(pReader) + 1;
        }

        return res;
    }
    CATCH_EXCEPTION
}

List<Scoped<Card>> scard::Context::GetCards(
    Scoped<Buffer> atr
)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        List<Scoped<Card>> res;
        SCARDCONTEXT hContext = *context.get();
        std::string cards;
        CHAR* pCard = NULL;
        DWORD dwSize = 0;
        NTSTATUS status = SCARD_S_SUCCESS;
        PBYTE pAtr = atr.get() ? atr->data() : NULL;

        status = SCardListCards(hContext, pAtr, NULL, 0, NULL, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardListCards");
        }
        cards.resize(dwSize);
        CHAR *pCards = (CHAR *)cards.c_str();
        status = SCardListCards(hContext, pAtr, NULL, 0, pCards, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardListCards");
        }

        pCard = (LPSTR)cards.c_str();
        while ('\0' != *pCard)
        {
            Scoped<std::string> name(new std::string(pCard));
            Scoped<Card> card(new Card(context, name));
            res.push_back(card);

            // Advance to the next value.
            pCard = pCard + strlen(pCard) + 1;
        }

        return res;
    }
    CATCH_EXCEPTION
}

scard::Reader::Reader(Scoped<SCARDCONTEXT> context, Scoped<std::string> name) :
    context(context),
    name(name),
    handle(NULL),
    activateProtocol(0)
{

}

scard::Reader::~Reader()
{
    try {
        Disconnect();
    }
    catch (Scoped<core::Exception> e) {
        LOGGER_ERROR(e->what());
    }
}

void scard::Reader::Connect(DWORD dwShareMode, DWORD dwPreferredProtocols)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SCARDCONTEXT hContext = *context.get();
        NTSTATUS status = SCARD_S_SUCCESS;

        if (handle) {
            SCardDisconnect(handle, SCARD_LEAVE_CARD);
            handle = NULL;
        }
        
        status = SCardConnect(hContext, name->c_str(), dwShareMode, dwPreferredProtocols, &handle, &activateProtocol);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardConnect");
        }
    }
    CATCH_EXCEPTION
}

void scard::Reader::Disconnect(DWORD flag)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status = SCARD_S_SUCCESS;

        if (handle) {
            status = SCardDisconnect(handle, flag);
            handle = NULL;
            if (status) {
                THROW_SCARD_EXCEPTION(status, "SCardDisconnect");
            }
        }
    }
    CATCH_EXCEPTION
}

BOOL scard::Reader::HasProviderName(DWORD dwProviderId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SCARDCONTEXT hContext = *context.get();
        DWORD dwSize = 0;

        NTSTATUS status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, NULL, &dwSize);
        return status == SCARD_S_SUCCESS;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> scard::Reader::GetProviderName(DWORD dwProviderId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SCARDCONTEXT hContext = *context.get();
        DWORD dwSize = 0;
        Scoped<std::string> provider(new std::string(""));
        LPSTR szProvider = NULL;

        NTSTATUS status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, NULL, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetCardTypeProviderName");
        }
        provider->resize(dwSize);
        szProvider = (char *)provider->c_str();
        status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, szProvider, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetCardTypeProviderName");
        }

        return provider;
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> scard::Reader::GetAttributeBytes(DWORD attrId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> buf(new Buffer(0));
        DWORD dwSize = 0;

        NTSTATUS status = SCardGetAttrib(handle, SCARD_ATTR_ATR_STRING, 0, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetAttrib");
        }
        buf->resize(dwSize);
        status = SCardGetAttrib(handle, SCARD_ATTR_ATR_STRING, buf->data(), &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetAttrib");
        }

        return buf;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> scard::Reader::GetAttributeString(DWORD attrId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        auto attr = GetAttributeBytes(attrId);
        return Scoped<std::string>(new std::string((char *)attr->data()));
    }
    CATCH_EXCEPTION
}

scard::Card::Card(Scoped<SCARDCONTEXT> context, Scoped<std::string> name) :
    context(context),
    name(name)
{
}

BOOL scard::Card::HasProviderName(DWORD dwProviderId)
{
    SCARDCONTEXT hContext = *context.get();
    DWORD dwSize = 0;

    NTSTATUS status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, NULL, &dwSize);
    return status == SCARD_S_SUCCESS;
}

Scoped<std::string> scard::Card::GetProviderName(DWORD dwProviderId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SCARDCONTEXT hContext = *context.get();
        DWORD dwSize = 0;
        Scoped<std::string> provider(new std::string(""));
        LPSTR szProvider = NULL;

        NTSTATUS status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, NULL, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetCardTypeProviderName");
        }
        provider->resize(dwSize);
        szProvider = (char *)provider->c_str();
        status = SCardGetCardTypeProviderName(hContext, name->c_str(), dwProviderId, szProvider, &dwSize);
        if (status != SCARD_S_SUCCESS) {
            THROW_SCARD_EXCEPTION(status, "SCardGetCardTypeProviderName");
        }

        return provider;
    }
    CATCH_EXCEPTION
}
