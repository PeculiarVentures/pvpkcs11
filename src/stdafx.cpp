#include "stdafx.h"

void SET_STRING(CK_UTF8CHAR* storage, const char* data, int size) {
    memset(storage, ' ', size);
    memcpy(storage, data, strlen(data));
}
