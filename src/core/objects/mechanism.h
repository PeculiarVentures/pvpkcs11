#pragma once

class Mechanism
{
public:

	CK_MECHANISM_TYPE     type;
	CK_ULONG              ulMinKeySize;
	CK_ULONG              ulMaxKeySize;
	CK_FLAGS              flags;

	Mechanism(
		CK_MECHANISM_TYPE     type,
		CK_ULONG              ulMinKeySize,
		CK_ULONG              ulMaxKeySize,
		CK_FLAGS              flags
	);
	~Mechanism();
};

