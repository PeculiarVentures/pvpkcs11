#include "ec_key.h"

using namespace core;

// Private Key

EcPrivateKey::EcPrivateKey() :
    PrivateKey()
{
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

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
    LOGGER_FUNCTION_BEGIN;
    LOGGER_DEBUG("New %s", __FUNCTION__);

    try {
        ItemByType(CKA_KEY_TYPE)->To<AttributeNumber>()->Set(CKK_EC);
        ItemByType(CKA_KEY_GEN_MECHANISM)->To<AttributeNumber>()->Set(CKM_ECDSA_KEY_PAIR_GEN);

        Add(AttributeBytes::New(CKA_ECDSA_PARAMS, NULL, 0, PVF_1 | PVF_3));
        Add(AttributeBytes::New(CKA_EC_POINT, NULL, 0, PVF_1 | PVF_4));
    }
    CATCH_EXCEPTION
}

// EC utils

Scoped<Buffer> EcUtils::getData(
    Scoped<Buffer>          data
)
{
    CK_BBOOL octet = false;
    for (CK_ULONG i = 0; i < data->size(); i++) {
        if (data->at(i) == 4) {
            if (octet) {
                Scoped<Buffer> res(new Buffer(data->size() - i));
                memcpy(res->data(), &data->at(i), res->size());
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
    Scoped<Buffer>          data,
    CK_ULONG                size
)
{
    try {
        data = getData(data);

        if ((data->size() == 0) || (data->at(0) != 4)) {
            THROW_EXCEPTION("Only uncompressed point format supported");
        }
        // Per ANSI X9.62, an encoded point is a 1 byte type followed by
        // ceiling(log base 2 field-size / 8) bytes of x and the same of y.
        if (size * 2 != data->size() - 1) {
            THROW_EXCEPTION("Point does not match field size");
        }

        Scoped<EcPoint> point(new EcPoint());
        point->X->resize(size);
        memcpy(point->X->data(), &data->at(1), size);

        point->Y->resize(size);
        memcpy(point->Y->data(), &data->at(size + 1), size);

        return point;
    }
    CATCH_EXCEPTION;
}

Scoped<Buffer> EcUtils::EncodePoint(
    Scoped<Buffer>          x,
    Scoped<Buffer>          y,
    CK_ULONG                size
)
{
    try {
        Scoped<Buffer> xb = PadZeroes(x, size);
        Scoped<Buffer> yb = PadZeroes(y, size);
        if ((xb->size() > size) || (yb->size() > size)) {
            THROW_EXCEPTION("Point coordinates do not match field size");
        }

        // ASN1 encode OCTET_STRING
        Scoped<Buffer> asn1Length = EncodeAsn1Length(1 + 2 * size);
        Scoped<Buffer> res(new Buffer);
        res->push_back(0x04);
        res->insert(res->end(), asn1Length->begin(), asn1Length->end());
        res->push_back(0x04);
        res->insert(res->end(), xb->begin(), xb->end());
        res->insert(res->end(), yb->begin(), yb->end());

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> EcUtils::PadZeroes(
    Scoped<Buffer>          buffer,
    CK_ULONG                size
)
{
    try {
        Scoped<Buffer> pad(new Buffer(size - buffer->size(), 0));
        memcpy(&pad->at(size), &buffer->at(0), buffer->size());
        return pad;
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> EcUtils::EncodeAsn1Length(
    CK_ULONG        length
)
{
    try {
        Scoped<Buffer> enc(new Buffer);
        if (length != (length & 0x7F)) {
            THROW_EXCEPTION("Too big length for ASN1 encoding");
        }
        else {
            enc->push_back(length);
        }
        return enc;
    }
    CATCH_EXCEPTION
}
