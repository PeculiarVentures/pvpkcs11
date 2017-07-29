#pragma once

#include "../../stdafx.h"
#include "../excep.h"
#include "private_key.h"
#include "public_key.h"

namespace core {

    static const char EC_P192_BLOB[] = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x01";
    static const char EC_P256_BLOB[] = "\x06\x08\x2A\x86\x48\xCE\x3D\x03\x01\x07";
    static const char EC_P384_BLOB[] = "\x06\x05\x2B\x81\x04\x00\x22";
    static const char EC_P521_BLOB[] = "\x06\x05\x2B\x81\x04\x00\x23";

    class EcPrivateKey : public PrivateKey {
    public:
        EcPrivateKey();
    };

    class EcPublicKey : public PublicKey {
    public:
        EcPublicKey();
    };

    struct EcPoint {
        EcPoint() : 
            X(Scoped<Buffer>(new Buffer)), 
            Y(Scoped<Buffer>(new Buffer)) 
        {}

        Scoped<Buffer> X;
        Scoped<Buffer> Y;
    };

    class EcUtils {
    public:
        static Scoped<EcPoint> DecodePoint(
            Scoped<Buffer>          data,
            CK_ULONG                size
        );

    protected:
        static Scoped<Buffer> getData(
            Scoped<Buffer>          data
        );

        static Scoped<Buffer> EncodePoint(
            Scoped<Buffer>          x,
            Scoped<Buffer>          y,
            CK_ULONG                size
        );

        static Scoped<Buffer> PadZeroes(
            Scoped<Buffer>          buffer,
            CK_ULONG                size
        );

        static Scoped<Buffer> EncodeAsn1Length(
            CK_ULONG                length
        );

    };

}