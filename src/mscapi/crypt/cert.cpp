#include "crypt.h"
#include "../ncrypt.h"

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
    if (context) {
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
        THROW_MSCAPI_EXCEPTION();
    }
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
        Scoped<Buffer> data(new Buffer());
        ULONG ulDataLen;
        if (!CertGetCertificateContextProperty(
            context,
            dwPropId,
            NULL,
            &ulDataLen
        )) {
            THROW_MSCAPI_EXCEPTION();
        }
        data->resize(ulDataLen);
        if (!CertGetCertificateContextProperty(
            context,
            dwPropId,
            data->data(),
            &ulDataLen
        )) {
            THROW_MSCAPI_EXCEPTION();
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
            THROW_MSCAPI_EXCEPTION();
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
            data->size(),   // cbData
            data->data()    // pbData
        };

        if (!CertSetCertificateContextProperty(
            context,
            dwPropId,
            dwFlags,
            &dataBlob
        )) {
            THROW_MSCAPI_EXCEPTION();
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
            THROW_MSCAPI_EXCEPTION();
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
            THROW_MSCAPI_EXCEPTION();
        }

        Assign(context);
    }
    CATCH_EXCEPTION
}