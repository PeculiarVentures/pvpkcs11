#pragma once

#include "../core/slot.h";

class MscapiSlot : public Slot {
public:
	MscapiSlot();

protected:
	Scoped<Session> CreateSession();
};
