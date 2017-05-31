#include "stdafx.h"

#include <CommonCrypto/CommonCrypto.h>;

void SET_STRING(CK_UTF8CHAR* storage, char* data, int size) {
    memset(storage, ' ', size);
    memcpy(storage, data, strlen(data));
}