#include "crypto.h"

#include "rsa.h"

using namespace mscapi;

typedef
_Check_return_
SECURITY_STATUS
WINAPI
ncryptFn(
    _In_    NCRYPT_KEY_HANDLE hKey,
    _In_reads_bytes_opt_(cbInput) PBYTE pbInput,
    _In_    DWORD   cbInput,
    _In_opt_    VOID *pPaddingInfo,
    _Out_writes_bytes_to_opt_(cbOutput, *pcbResult) PBYTE pbOutput,
    _In_    DWORD   cbOutput,
    _Out_   DWORD * pcbResult,
    _In_    DWORD   dwFlags);

CryptoRsaOAEPEncrypt::CryptoRsaOAEPEncrypt(
    CK_BBOOL type
) :
    CryptoEncrypt(type)
{

}

CK_RV CryptoRsaOAEPEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    key
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        if (pMechanism->mechanism != CKM_RSA_PKCS_OAEP) {
            THROW_PKCS11_MECHANISM_INVALID();
        }
        // Check parameters
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        CK_RSA_PKCS_OAEP_PARAMS_PTR params = static_cast<CK_RSA_PKCS_OAEP_PARAMS_PTR>(pMechanism->pParameter);
        if (params == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is not CK_RSA_PKCS_OAEP_PARAMS");
        }
        switch (params->hashAlg) {
        case CKM_SHA_1:
            digestAlg = NCRYPT_SHA1_ALGORITHM;
            break;
        case CKM_SHA256:
            digestAlg = NCRYPT_SHA256_ALGORITHM;
            break;
        case CKM_SHA384:
            digestAlg = NCRYPT_SHA384_ALGORITHM;
            break;
        case CKM_SHA512:
            digestAlg = NCRYPT_SHA512_ALGORITHM;
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "Wrong hashAlg");
        }
        if (params->pSourceData) {
            label = std::string((PCHAR)params->pSourceData, params->ulSourceDataLen);
        }
        else {
            label = std::string("");
        }

        CryptoKey* cryptoKey = NULL; 
        if (this->type == CRYPTO_ENCRYPT) {
            cryptoKey = dynamic_cast<RsaPublicKey*>(key.get());
        }
        else {
            cryptoKey = dynamic_cast<RsaPrivateKey*>(key.get());
        }
        if (!cryptoKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "");
        }
        this->key = cryptoKey->GetNKey();
        hKey = this->key->Get();

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoRsaOAEPEncrypt::Once(
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        if (!active) {
            THROW_PKCS11_OPERATION_NOT_INITIALIZED();
        }

        BCRYPT_OAEP_PADDING_INFO paddingInfo = {
            digestAlg,                                              // pszAlgId
            (PUCHAR)    (label.length() ? label.c_str() : NULL),    // pbLabel
            (ULONG)     label.length()                              // cbLabel
        };

        ncryptFn* fn;

        if (type == CRYPTO_ENCRYPT) {
            fn = &NCryptEncrypt;
        }
        else {
            fn = &NCryptDecrypt;
        }

        NTSTATUS status;
        if (pEncryptedData == NULL) {
            status = fn(
                hKey,
                pData, ulDataLen,
                &paddingInfo,
                NULL,
                0,
                pulEncryptedDataLen,
                BCRYPT_PAD_OAEP
            );
        }
        else {
            status = fn(
                hKey,
                pData, ulDataLen,
                &paddingInfo,
                pEncryptedData,
                *pulEncryptedDataLen,
                pulEncryptedDataLen,
                BCRYPT_PAD_OAEP
            );
        }

        if (status) {
            if (status == NTE_BUFFER_TOO_SMALL) {
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            if (status == NTE_PERM) {
                THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "The key identified by the hKey parameter cannot be used for decryption.");
            }
            active = false;
            THROW_NT_EXCEPTION(status);
        }

        active = false;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoRsaOAEPEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        THROW_PKCS11_MECHANISM_INVALID();
    }
    CATCH_EXCEPTION
}

CK_RV CryptoRsaOAEPEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        active = false;
        THROW_PKCS11_MECHANISM_INVALID();
    }
    CATCH_EXCEPTION
}