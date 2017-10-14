#include "key.h"

using namespace core;

Key::Key() :
    Storage()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        Add(AttributeNumber::New(CKA_KEY_TYPE, 0, PVF_1 | PVF_5));
        Add(AttributeBytes::New(CKA_ID, NULL, 0, PVF_8));
        Add(AttributeBytes::New(CKA_START_DATE, NULL, 0, PVF_8));
        Add(AttributeBytes::New(CKA_END_DATE, NULL, 0, PVF_8));
        Add(AttributeBool::New(CKA_DERIVE, false, PVF_8));
        Add(AttributeBool::New(CKA_LOCAL, false, PVF_2 | PVF_4 | PVF_6));
        Add(AttributeNumber::New(CKA_KEY_GEN_MECHANISM, 0, PVF_2 | PVF_4 | PVF_6));
        Add(AttributeAllowedMechanisms::New(CKA_ALLOWED_MECHANISMS, NULL, 0, 0));
    }
    CATCH_EXCEPTION
}