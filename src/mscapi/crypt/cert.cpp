#include "crypt.h"
#include "../ncrypt.h"
#include "../bcrypt.h"

using namespace crypt;

Certificate::Certificate() :
    context(NULL)
{}

Certificate::~Certificate()
{
    Destroy();
}

void Certificate::Destroy()
{
    if (context != NULL) {
        CertFreeCertificateContext(context);
        context = NULL;
    }
}

void Certificate::Assign(
    PCCERT_CONTEXT context
)
{
    try {
        Destroy();
        this->context = context;
    }
    CATCH_EXCEPTION
}

PCCERT_CONTEXT Certificate::Get()
{
    return context;
}

Scoped<Certificate> Certificate::Duplicate()
{
    Scoped<Certificate> res(new Certificate());
    res->context = CertDuplicateCertificateContext(context);
    if (!res->context) {
        THROW_MSCAPI_EXCEPTION("CertDuplicateCertificateContext");
    }

    return res;
}

bool Certificate::HasProperty(
    DWORD dwPropId
)
{
    ULONG ulDataLen;
    return CertGetCertificateContextProperty(context, dwPropId, NULL, &ulDataLen);
}

Scoped<Buffer> Certificate::GetPropertyBytes(
    DWORD dwPropId
) {
    try {
        Scoped<Buffer> data(new Buffer(0));
        ULONG ulDataLen;
        if (!CertGetCertificateContextProperty(
            context,
            dwPropId,
            NULL,
            &ulDataLen
        )) {
            THROW_MSCAPI_EXCEPTION("CertGetCertificateContextProperty");
        }
        data->resize(ulDataLen);
        if (!CertGetCertificateContextProperty(
            context,
            dwPropId,
            data->data(),
            &ulDataLen
        )) {
            THROW_MSCAPI_EXCEPTION("CertGetCertificateContextProperty");
        }

        return data;
    }
    CATCH_EXCEPTION
}

ULONG Certificate::GetPropertyNumber(
    DWORD dwPropId
) {
    try {
        ULONG data;
        ULONG ulDataLen = sizeof(ULONG);
        if (!CertGetCertificateContextProperty(
            context,
            dwPropId,
            &data,
            &ulDataLen
        )) {
            THROW_MSCAPI_EXCEPTION("CertGetCertificateContextProperty");
        }

        return data;
    }
    CATCH_EXCEPTION
}

void Certificate::SetPropertyBytes(
    DWORD           dwPropId,
    Buffer*         data,
    DWORD           dwFlags
) {
    try {
        CRYPT_DATA_BLOB dataBlob = {
            (ULONG) data->size(),           // cbData
            data->data()                    // pbData
        };

        if (!CertSetCertificateContextProperty(
            context,
            dwPropId,
            dwFlags,
            &dataBlob
        )) {
            THROW_MSCAPI_EXCEPTION("CertSetCertificateContextProperty");
        }
    }
    CATCH_EXCEPTION
}

void Certificate::SetPropertyNumber(
    DWORD           dwPropId,
    DWORD           data,
    DWORD           dwFlags
) {
    try {
        if (!CertSetCertificateContextProperty(
            context,
            dwPropId,
            dwFlags,
            &data
        )) {
            THROW_MSCAPI_EXCEPTION("CertSetCertificateContextProperty");
        }
    }
    CATCH_EXCEPTION
}

void Certificate::Import(
    PUCHAR  pbEncoded,
    DWORD   cbEncoded
)
{
    try {
        PCCERT_CONTEXT context = CertCreateCertificateContext(
            X509_ASN_ENCODING,
            pbEncoded,
            cbEncoded
        );
        if (!context) {
            THROW_MSCAPI_EXCEPTION("CertCreateCertificateContext");
        }

        Assign(context);
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
        } else {
            return Scoped<std::string>(new std::string(name));
        }
    }
    CATCH_EXCEPTION
}

void Certificate::DeleteFromStore()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (context->hCertStore) {
            BOOL res = CertDeleteCertificateFromStore(context);
            //  NOTE: the pCertContext is always CertFreeCertificateContext'ed by
            //  this function, even for an error.
            context = NULL;
            if (!res) {
                THROW_MSCAPI_EXCEPTION("CertDeleteCertificateFromStore");
            }
        }
    }
    CATCH_EXCEPTION
}

Scoped<ncrypt::Key> crypt::Certificate::GetPublicKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<ncrypt::Key> publicKey();

        if (HasPrivateKey()) {
            Scoped<ProviderInfo> provInfo = GetProviderInfo();

            ALG_ID dwAlgId = CertOIDToAlgId(context->pCertInfo->SubjectPublicKeyInfo.Algorithm.pszObjId);
            DWORD dwProvType = PROV_RSA_FULL;
            switch (dwAlgId) {
            case CALG_ECDH:
            case CALG_ECDSA:
                dwProvType = PROV_EC_ECDSA_FULL;
            }

            /*ncrypt::Provider prov;
            prov.Open(MS_KEY_STORAGE_PROVIDER, 0);

            NCRYPT_KEY_HANDLE hKey = NULL;

            SECURITY_STATUS status = NCryptImportKey(prov.Get(), NULL, BCRYPT_PUBLIC_KEY_BLOB, NULL, &hKey, context->pCertInfo->SubjectPublicKeyInfo.PublicKey.pbData, context->pCertInfo->SubjectPublicKeyInfo.PublicKey.cbData, 0);
            if (status) {
                THROW_NT_EXCEPTION(status);
            }

            return Scoped<ncrypt::Key>(new ncrypt::Key(hKey));*/

            BCRYPT_KEY_HANDLE bKey = NULL;

            if (!CryptImportPublicKeyInfoEx2(X509_ASN_ENCODING, &context->pCertInfo->SubjectPublicKeyInfo, 0, NULL, &bKey)) {
                THROW_MSCAPI_EXCEPTION("CryptImportPublicKeyInfoEx2");
            }

            bcrypt::Key bcryptKey(bKey);

            return bcryptKey.ToNKey();
        }
        else {
            THROW_EXCEPTION("Cannot get public key for certificate '%s'. ", GetName()->c_str());
        }

    }
    CATCH_EXCEPTION
}

CK_BBOOL crypt::Certificate::HasPrivateKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        return HasProperty(CERT_KEY_PROV_INFO_PROP_ID);
    }
    CATCH_EXCEPTION
}

Scoped<ProviderInfo> crypt::Certificate::GetProviderInfo()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        Scoped<Buffer> propKeyProvInfo = GetPropertyBytes(CERT_KEY_PROV_INFO_PROP_ID);

        return Scoped<ProviderInfo>(new ProviderInfo(propKeyProvInfo));
    }
    CATCH_EXCEPTION
}