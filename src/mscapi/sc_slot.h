#pragma once

#include "../core/slot.h"

namespace mscapi {

    class SmartCardSlot : public core::Slot {
    public:
        Scoped<std::string> readerName;
        Scoped<std::string> provName;
        // Type of crypto provider
        // - SCARD_PROVIDER_CSP
        // - SCARD_PROVIDER_KSP
        DWORD               provType;

        // Constructor
        // name - SmartCard reader name
        SmartCardSlot(
            PCCH        readerName,
            PCCH        provName,
            DWORD       provType
        );

    protected:
        Scoped<core::Session> CreateSession();
    };

}