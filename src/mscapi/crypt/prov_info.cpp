#include "prov_info.h"

#include "../helper.h"

using namespace crypt;

ProviderInfo::ProviderInfo(Scoped<Buffer> info) :
    buffer(info),
    info((CRYPT_KEY_PROV_INFO*)info->data())
{
}


ProviderInfo::~ProviderInfo()
{
}

CRYPT_KEY_PROV_INFO * ProviderInfo::Get()
{
    return info;
}