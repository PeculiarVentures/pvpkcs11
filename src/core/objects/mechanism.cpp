#include "../../stdafx.h"
#include "mechanism.h"

using namespace core;

Mechanism::Mechanism(
	CK_MECHANISM_TYPE     type,
	CK_ULONG              ulMinKeySize,
	CK_ULONG              ulMaxKeySize,
	CK_FLAGS              flags
)
{
	this->type = type;
	this->ulMinKeySize = ulMinKeySize;
	this->ulMaxKeySize = ulMaxKeySize;
	this->flags = flags;
}


Mechanism::~Mechanism()
{
}
