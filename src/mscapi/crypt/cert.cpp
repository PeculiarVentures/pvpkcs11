#include "cert.h"
#include "../helper.h"
#include "../crypto.h"

using namespace crypt;

void crypt::Certificate::Dispose()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!IsEmpty()) {
            CertFreeCertificateContext(Get());
            Handle::Dispose();
        }
    }
    CATCH_EXCEPTION
}

Scoped<Certificate> crypt::Certificate::Duplicate()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Certificate> res(new Certificate);
        
        PCCERT_CONTEXT copyCert = CertDuplicateCertificateContext(Get());
        if (!copyCert) {
            THROW_MSCAPI_EXCEPTION("CertDuplicateCertificateContext");
        }

        res->Set(copyCert);
        return res;
    }
    CATCH_EXCEPTION

}

BOOL crypt::Certificate::HasPrivateKey()
{
    LOGGER_FUNCTION_BEGIN;

    return HasProperty(CERT_KEY_PROV_INFO_PROP_ID);
}

Scoped<Buffer> crypt::Certificate::GetID()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        CRYPT_BIT_BLOB* pubKeyBlob = &Get()->pCertInfo->SubjectPublicKeyInfo.PublicKey;

        return DIGEST_SHA1(pubKeyBlob->pbData, pubKeyBlob->cbData);
    }
    CATCH_EXCEPTION
}

Scoped<mscapi::CryptoKey> crypt::Certificate::GetPublicKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return mscapi::CryptoKey::Create(&Get()->pCertInfo->SubjectPublicKeyInfo);
    }
    CATCH_EXCEPTION
}

Scoped<mscapi::CryptoKey> crypt::Certificate::GetPrivateKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return Scoped<mscapi::CryptoKey>(new mscapi::CryptoKey(GetProviderInfo()));
    }
    CATCH_EXCEPTION
}

Scoped<std::string> crypt::Certificate::GetName()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        char name[512] = { 0 };
        DWORD nameLen = CertGetNameStringA(Get(), CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, 0, name, 512);

        if (nameLen <= 1) {
            return Scoped<std::string>(new std::string("Unknow certificate"));
        }
        else {
            return Scoped<std::string>(new std::string(name));
        }
    }
    CATCH_EXCEPTION
}

Scoped<crypt::ProviderInfo> crypt::Certificate::GetProviderInfo()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> provInfoBuf = GetBytes(CERT_KEY_PROV_INFO_PROP_ID);

        return Scoped<ProviderInfo>(new ProviderInfo(provInfoBuf));
    }
    CATCH_EXCEPTION
}

BOOL crypt::Certificate::HasProperty(DWORD dwPropId)
{
    LOGGER_FUNCTION_BEGIN;

    DWORD dataLen = 0;
    return CertGetCertificateContextProperty(Get(), dwPropId, NULL, &dataLen);
}

void crypt::Certificate::GetProperty(DWORD dwPropId, PBYTE pbData, PDWORD pdwDataLen)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CertGetCertificateContextProperty(Get(), dwPropId, pbData, pdwDataLen)) {
            THROW_MSCAPI_EXCEPTION("CertGetCertificateContextProperty");
        }
    }
    CATCH_EXCEPTION
}

Scoped<Buffer> crypt::Certificate::GetBytes(DWORD dwPropId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> res(new Buffer(0));
        DWORD resLen = 0;

        GetProperty(dwPropId, NULL, &resLen);
        res->resize(resLen);
        GetProperty(dwPropId, res->data(), &resLen);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::string> crypt::Certificate::GetString(DWORD dwPropId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<std::string> res(new std::string(""));
        DWORD resLen = 0;

        GetProperty(dwPropId, NULL, &resLen);
        res->resize(resLen);
        GetProperty(dwPropId, (PBYTE)res->c_str(), &resLen);

        return res;
    }
    CATCH_EXCEPTION
}

DWORD crypt::Certificate::GetNumber(DWORD dwPropId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        DWORD res = 0;
        DWORD resLen = sizeof(res);

        GetProperty(dwPropId, (PBYTE)&res, &resLen);

        return res;
    }
    CATCH_EXCEPTION
}

Scoped<std::wstring> crypt::Certificate::GetStringW(DWORD dwPropId)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<std::wstring> res(new std::wstring(L""));
        DWORD resLen = 0;

        GetProperty(dwPropId, NULL, &resLen);
        res->resize(resLen);
        GetProperty(dwPropId, (PBYTE)res->c_str(), &resLen);

        return res;
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::SetProperty(DWORD dwPropId, PBYTE pbData, DWORD dwFlag)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!CertSetCertificateContextProperty(Get(), dwPropId, dwFlag, pbData)) {
            THROW_MSCAPI_EXCEPTION("CertSetCertificateContextProperty");
        }
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::SetBytes(DWORD dwPropId, Scoped<Buffer> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetProperty(dwPropId, value->data());
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::SetString(DWORD dwPropId, Scoped<std::string> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        SetProperty(dwPropId, (PBYTE)value->c_str());
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::SetStringW(DWORD dwPropId, Scoped<std::wstring> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        std::string str(value->begin(), value->end());
        SetProperty(dwPropId, (PBYTE)str.c_str());
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::DeleteFromStore()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (Get()->hCertStore) {
            BOOL res = CertDeleteCertificateFromStore(Get());
            //  NOTE: the pCertContext is always CertFreeCertificateContext'ed by
            //  this function, even for an error.
            Handle::Dispose();
            if (!res) {
                THROW_MSCAPI_EXCEPTION("CertDeleteCertificateFromStore");
            }
        }
    }
    CATCH_EXCEPTION
}

void crypt::Certificate::Import(PUCHAR pbData, DWORD dwDataLen)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        PCCERT_CONTEXT context = CertCreateCertificateContext(
            X509_ASN_ENCODING,
            pbData,
            dwDataLen
        );
        if (!context) {
            THROW_MSCAPI_EXCEPTION("CertCreateCertificateContext");
        }

        Set(context);
    }
    CATCH_EXCEPTION
}