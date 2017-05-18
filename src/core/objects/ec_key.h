#pragma once

#include "../../stdafx.h"
#include "../excep.h"
#include "private_key.h"
#include "public_key.h"

namespace core {

    static const char EC_P192_BLOB[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
    static const char EC_P256_BLOB[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
    static const char EC_P384_BLOB[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
    static const char EC_P521_BLOB[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

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
        static Scoped<Buffer> EcUtils::getData(
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