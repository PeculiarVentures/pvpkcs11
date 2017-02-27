#pragma once

#include "../core/slot.h";

class MscapiSession : public Slot {
public:
	MscapiSession();

protected:
	Scoped<Session> CreateSession();
};
