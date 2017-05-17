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
        std::vector<CK_BYTE> X;
        std::vector<CK_BYTE> Y;
    };

    class EcUtils {
    public:
        static Scoped<EcPoint> DecodePoint(
            std::vector<CK_BYTE>    data,
            CK_ULONG                size
        );

    protected:
        static std::vector<CK_BYTE> EcUtils::getData(
            std::vector<CK_BYTE>    data
        );

        static std::vector<CK_BYTE> EncodePoint(
            std::vector<CK_BYTE>    x,
            std::vector<CK_BYTE>    y,
            CK_ULONG                size
        );

        static std::vector<CK_BYTE> PadZeroes(
            std::vector<CK_BYTE>    buffer,
            CK_ULONG                size
        );

        static std::vector<CK_BYTE> EncodeAsn1Length(
            CK_ULONG                length
        );

    };

}