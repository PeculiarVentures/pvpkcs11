#pragma Once

#include "../stdafx.h"
#include "../core/slot.h"

namespace osx {

    class Slot : public core::Slot {
	public:
		Slot();

	protected:
		Scoped<core::Session> CreateSession();
	};

}