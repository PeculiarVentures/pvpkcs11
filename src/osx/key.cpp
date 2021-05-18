#include "key.h"

using namespace osx;

Scoped<SecKey> osx::Key::Get()
{
    return value;
}
