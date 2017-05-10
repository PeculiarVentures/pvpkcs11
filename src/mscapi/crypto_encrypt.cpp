#include "crypto.h"

using namespace mscapi;

CryptoRsaOAEPEncrypt::CryptoRsaOAEPEncrypt(
    CK_BBOOL type
):
    CryptoEncrypt(type)
{

}

CK_RV CryptoRsaOAEPEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    hKey
)
{
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
    try {
    }
    CATCH_EXCEPTION
}

CK_RV CryptoRsaOAEPEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
    try {
    }
    CATCH_EXCEPTION
}