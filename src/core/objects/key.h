#pragma once

#include "storage.h"

class Key : public Storage {

public:
	Key();

	CK_RV GetAttributeValue
	(
		CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes; gets values */
		CK_ULONG          ulCount     /* attributes in template */
	);

	virtual DECLARE_GET_ATTRIBUTE(GetKeyType);
	virtual DECLARE_GET_ATTRIBUTE(GetID);
	virtual DECLARE_GET_ATTRIBUTE(GetStartDate);
	virtual DECLARE_GET_ATTRIBUTE(GetEndDate);
	virtual DECLARE_GET_ATTRIBUTE(GetDerive);
	virtual DECLARE_GET_ATTRIBUTE(GetLocal);
	virtual DECLARE_GET_ATTRIBUTE(GetKeyGenMechanism);
	virtual DECLARE_GET_ATTRIBUTE(GetAllowedMechanisms);

	CK_ULONG     propKeyType;
	std::string  propId;
	CK_BBOOL     propDerive;

};