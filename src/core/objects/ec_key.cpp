#include "ec_key.h"

using namespace core;

// Private Key

EcPrivateKey::EcPrivateKey() :
    PrivateKey()
{
    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_EC);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_ECDSA_KEY_PAIR_GEN);

        Add(AttributeBytes::New(CKA_ECDSA_PARAMS, NULL, 0, PVF_1 | PVF_4 | PVF_6));
        Add(AttributeBytes::New(CKA_VALUE, NULL, 0, PVF_1 | PVF_4 | PVF_6 | PVF_7));
    }
    CATCH_EXCEPTION
}

// Public Key

EcPublicKey::EcPublicKey() :
    PublicKey()
{
    ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_EC);
    ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_ECDSA_KEY_PAIR_GEN);

    Add(AttributeBytes::New(CKA_ECDSA_PARAMS, NULL, 0, PVF_1 | PVF_3));
    Add(AttributeBytes::New(CKA_EC_POINT, NULL, 0, PVF_1 | PVF_4));
}

// EC utils

std::vector<CK_BYTE> EcUtils::getData(
    std::vector<CK_BYTE> data
)
{
    CK_BBOOL octet = false;
    for (CK_ULONG i = 0; i < data.size(); i++) {
        if (data[i] == 4) {
            if (octet) {
                std::vector<CK_BYTE> res(data.size() - i);
                memcpy(&res[0], &data[i], res.size());
                return res;
            }
            else {
                octet = true;
            }
        }
    }
    THROW_EXCEPTION("Wrong data");
}

// Used by SunPKCS11 and SunJSSE.
Scoped<EcPoint> EcUtils::DecodePoint(
    std::vector<CK_BYTE>    data,
    CK_ULONG                size
)
{
    try {
        data = getData(data);

        if ((data.size() == 0) || (data[0] != 4)) {
            THROW_EXCEPTION("Only uncompressed point format supported");
        }
        // Per ANSI X9.62, an encoded point is a 1 byte type followed by
        // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
        if (size * 2 != data.size() - 1) {
            THROW_EXCEPTION("Point does not match field size");
        }

        Scoped<EcPoint> point(new EcPoint());
        point->X.resize(size);
        memcpy(&point->X[0], &data[1], size);

        point->Y.resize(size);
        memcpy(&point->Y[0], &data[size + 1], 2 * size + 1);

        return point;
    }
    CATCH_EXCEPTION;
}

std::vector<CK_BYTE> EcUtils::EncodePoint(
    std::vector<CK_BYTE>    x,
    std::vector<CK_BYTE>    y,
    CK_ULONG                size
)
{
    try {
        auto xb = PadZeroes(x, size);
        auto yb = PadZeroes(y, size);
        if ((xb.size() > size) || (yb.size() > size)) {
            THROW_EXCEPTION("Point coordinates do not match field size");
        }

        // ASN1 encode OCTET_STRING
        std::vector<CK_BYTE> asn1Length = EncodeAsn1Length(1 + 2 * size);
        std::vector<CK_BYTE> res;
        res.push_back(0x04);
        res.insert(res.end(), asn1Length.begin(), asn1Length.end());
        res.push_back(0x04);
        res.insert(res.end(), xb.begin(), xb.end());
        res.insert(res.end(), yb.begin(), yb.end());

        return res;
    }
    CATCH_EXCEPTION
}

std::vector<CK_BYTE> EcUtils::PadZeroes(
    std::vector<CK_BYTE>    buffer,
    CK_ULONG                size
)
{
    try {
        std::vector<CK_BYTE> pad(size - buffer.size(), 0);
        memcpy(&pad[size], &buffer[0], buffer.size());
        return pad;
    }
    CATCH_EXCEPTION
}

std::vector<CK_BYTE> EcUtils::EncodeAsn1Length(
    CK_ULONG        length
)
{
    try {
        std::vector<CK_BYTE> enc;
        if (length != (length & 0x7F)) {
            THROW_EXCEPTION("Too big length for ASN1 encoding");
        }
        else {
            enc.push_back(length);
        }
        return enc;
    }
    CATCH_EXCEPTION
}
