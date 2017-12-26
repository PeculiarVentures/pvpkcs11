#pragma once

#include "../core/slot.h"

namespace mscapi {

    class SmartCardSlot : public core::Slot {
    public:
        Scoped<std::string> readerName;
        Scoped<std::string> provName;
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