#pragma once

#include "../core/slot.h"

namespace mscapi {

    class SystemSlot : public core::Slot {
    public:
        SystemSlot();

    protected:
        Scoped<core::Session> CreateSession();
    };

}