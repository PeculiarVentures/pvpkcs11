#pragma once

#include "../stdafx.h"

#include "objects/private_key.h"
#include "objects/public_key.h"

namespace core {

    class KeyPair {
    public:
        Scoped<PrivateKey>  privateKey;
        Scoped<PublicKey>   publicKey;
        
        KeyPair(Scoped<PrivateKey> privateKey, Scoped<PublicKey> publicKey);
    };

}
