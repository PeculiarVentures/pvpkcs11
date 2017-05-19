#include "data.h"

using namespace core;

Data::Data()
{
    try {
        ItemByType(CKA_CLASS)->To<AttributeNumber>()->Set(CKO_CERTIFICATE);

        Add(AttributeBytes::New(CKA_APPLICATION, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_OBJECT_ID, NULL, 0, 0));
        Add(AttributeBytes::New(CKA_VALUE, NULL, 0, 0));
    }
    CATCH_EXCEPTION;
}
