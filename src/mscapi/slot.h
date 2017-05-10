#pragma once

#include "../core/slot.h";

namespace mscapi {

	class Slot : public core::Slot {
	public:
		Slot();

	protected:
		Scoped<core::Session> CreateSession();
	};

}