#include "storage.h"

using namespace core;

Storage::Storage() :
    Object()
{
    // set props defaults
    Add(AttributeBool::New(CKA_TOKEN, false, PVF_13));
    Add(AttributeBool::New(CKA_PRIVATE, false, PVF_13));
    Add(AttributeBool::New(CKA_MODIFIABLE, true, PVF_13));
    Add(AttributeBytes::New(CKA_LABEL, NULL, 0, PVF_8)); // PVF_8 - no in spec
    Add(AttributeBool::New(CKA_COPYABLE, true, PVF_12));
}