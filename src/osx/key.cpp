#include "key.h"

using namespace osx;

SecKeyRef osx::Key::Get()
{
    return *value;
}
