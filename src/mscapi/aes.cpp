#include "aes.h"
#include "helper.h"

#include "bcrypt/provider.h"
#include "bcrypt/key.h"

using namespace mscapi;

Scoped<core::SecretKey> AesKey::Generate(
    CK_MECHANISM_PTR       pMechanism,                  /* key-gen mechanism */
    Scoped<core::Template> tmpl
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_AES_KEY_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        Scoped<AesKey> aesKey(new AesKey());
        aesKey->GenerateValues(tmpl->Get(), tmpl->Size());

        ULONG ulKeyLength = tmpl->GetNumber(CKA_VALUE_LEN, true, 0);

        switch (ulKeyLength) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE must be 16, 24 or 32");
        }

        Scoped<bcrypt::Provider> provider(new bcrypt::Provider);
        provider->Open(BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

        auto secretKey = provider->GenerateRandom(ulKeyLength);

        auto key = provider->GenerateKey(NULL, 0, secretKey->data(), secretKey->size(), 0);

        // Set properties

        aesKey->ItemByType(CKA_VALUE_LEN)->To<core::AttributeNumber>()->Set(ulKeyLength);
        aesKey->ItemByType(CKA_VALUE)->SetValue(secretKey->data(), secretKey->size());

        // AES keys are not copyable
        aesKey->ItemByType(CKA_COPYABLE)->To<core::AttributeBool>()->Set(CK_FALSE);

        aesKey->SetKey(key);

        return aesKey;
    }
    CATCH_EXCEPTION
}

CK_RV AesKey::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::Template tmpl(pTemplate, ulCount);
        core::AesKey::CreateValues(pTemplate, ulCount);

        NTSTATUS status;
        Scoped<Buffer> buffer(new Buffer);

        auto value = tmpl.GetBytes(CKA_VALUE, true, "");

        buffer->resize(sizeof(BCRYPT_KEY_DATA_BLOB_HEADER));
        BCRYPT_KEY_DATA_BLOB_HEADER* header = (BCRYPT_KEY_DATA_BLOB_HEADER*)buffer->data();
        header->dwMagic = BCRYPT_KEY_DATA_BLOB_MAGIC;
        header->dwVersion = BCRYPT_KEY_DATA_BLOB_VERSION1;
        header->cbKeyData = value->size();

        buffer->insert(buffer->end(), value->begin(), value->end());

        bcrypt::Provider provider;
        provider.Open(BCRYPT_AES_ALGORITHM, MS_PRIMITIVE_PROVIDER, 0);

        auto key = provider.ImportKey(BCRYPT_KEY_DATA_BLOB, buffer->data(), buffer->size(), 0);
        SetKey(key);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV mscapi::AesKey::Destroy()
{
	LOGGER_FUNCTION_BEGIN;

    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void mscapi::AesKey::SetKey(Scoped<bcrypt::Key> value)
{
    LOGGER_FUNCTION_BEGIN;

    try {
        key = value;
    }
    CATCH_EXCEPTION
}

Scoped<bcrypt::Key> mscapi::AesKey::GetKey()
{
    LOGGER_FUNCTION_BEGIN;

    try {
        if (!key.get()) {
            THROW_EXCEPTION("Key is empty");
        }
        return key;
    }
    CATCH_EXCEPTION
}

// AES-CBC

CryptoAesEncrypt::CryptoAesEncrypt(
    CK_BBOOL type
) : CryptoEncrypt(type)
{
}

CK_RV CryptoAesEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    key
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoEncrypt::Init(
            pMechanism,
            key
        );

        if (!(key && key.get())) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
        }
        auto castKey = dynamic_cast<AesKey*>(key.get());
        if (!castKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key must be AES");
        }
        this->key = castKey->GetKey()->Duplicate();

        mechanism = pMechanism->mechanism;

        switch (mechanism) {
        case CKM_AES_ECB: {
            padding = false;
            this->key->ChangeMode(BCRYPT_CHAIN_MODE_ECB);
            
            break;
        }
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD: {
            padding = mechanism == CKM_AES_CBC ? false : true;
            // IV
            if (pMechanism->pParameter == NULL_PTR) {
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
            }
            if (pMechanism->ulParameterLen != 16) {
                THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "AES-CBC IV must be 16 bytes");
            }
            iv = Scoped<std::string>(new std::string((PCHAR)pMechanism->pParameter, pMechanism->ulParameterLen));

            this->key->ChangeMode(BCRYPT_CHAIN_MODE_CBC);

            break;
        }
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        blockLength = this->key->GetNumber(BCRYPT_BLOCK_LENGTH);

        buffer = std::string("");

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        std::string data("");
        std::string incomingData((char*)pPart, ulPartLen);

        if (padding) {
            data = buffer + incomingData;
            DWORD dwModulo = data.length() % blockLength;
            if (dwModulo) {
                buffer = data.substr(data.length() - dwModulo, dwModulo);
                data.resize(data.length() - dwModulo);
            }
            else {
                if (type == CRYPTO_DECRYPT) {
                    // leave last BLOCK for final operation
                    // it's needed for PADDING removing
                    buffer = data.substr(data.length() - blockLength, blockLength);
                    data.resize(data.length() - blockLength);
                }
                else {
                    buffer.erase();
                }
            }
        }
        else {
            if (incomingData.length() % blockLength) {
                THROW_PKCS11_EXCEPTION(CKR_DATA_LEN_RANGE, "Wrong incoming data");
            }
            data = incomingData;
        }

        if (data.length()) {
            this->Make(false, (PUCHAR)data.c_str(), data.length(), pEncryptedPart, pulEncryptedPartLen);
        }
        else {
            *pulEncryptedPartLen = 0;
        }

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        if (type == CRYPTO_ENCRYPT || !buffer.empty()) {
            this->Make(true, (BYTE*)buffer.c_str(), buffer.length(), pLastEncryptedPart, pulLastEncryptedPartLen);
        }
        else {
            *pulLastEncryptedPartLen = 0;
        }

        active = false;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

void CryptoAesEncrypt::Make(
    bool    bFinal,
    BYTE*   pbData,
    DWORD   dwDataLen,
    BYTE*   pbOut,
    DWORD*  pdwOutLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        DWORD dwEncryptedLen;
        NTSTATUS status;
        ULONG dwPaddingFlag = bFinal && padding ? BCRYPT_BLOCK_PADDING : 0;

        PUCHAR  pbIV;
        ULONG   ulIVLen;

        if (mechanism == CKM_AES_ECB) {
            pbIV = NULL;
            ulIVLen = 0;
        }
        else {
            pbIV = (PUCHAR)iv->c_str();
            ulIVLen = iv->length();
        }

        if (type == CRYPTO_ENCRYPT) {
            if (status = BCryptEncrypt(key->Get(), pbData, dwDataLen, NULL, pbIV, ulIVLen, NULL, 0, &dwEncryptedLen, dwPaddingFlag)) {
                THROW_NT_EXCEPTION(status, "BCryptEncrypt");
            }
            if (pbData == NULL_PTR) {
                *pdwOutLen = dwEncryptedLen;
            }
            else if (*pdwOutLen < dwEncryptedLen) {
                *pdwOutLen = dwEncryptedLen;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                if (status = BCryptEncrypt(key->Get(), pbData, dwDataLen, NULL, pbIV, ulIVLen, pbOut, dwEncryptedLen, pdwOutLen, dwPaddingFlag)) {
                    THROW_NT_EXCEPTION(status, "BCryptEncrypt");
                }
            }
        }
        else {
            if (status = BCryptDecrypt(key->Get(), pbData, dwDataLen, NULL, pbIV, ulIVLen, NULL, 0, &dwEncryptedLen, dwPaddingFlag)) {
                THROW_NT_EXCEPTION(status, "BCryptDecrypt");
            }
            if (pbData == NULL_PTR) {
                *pdwOutLen = dwEncryptedLen;
            }
            else if (*pdwOutLen < dwEncryptedLen) {
                *pdwOutLen = dwEncryptedLen;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                if (status = BCryptDecrypt(key->Get(), pbData, dwDataLen, NULL, pbIV, ulIVLen, pbOut, dwEncryptedLen, pdwOutLen, dwPaddingFlag)) {
                    if (status == STATUS_DATA_ERROR) {
                        THROW_PKCS11_EXCEPTION(CKR_ENCRYPTED_DATA_INVALID, "Bad encrypted data");
                    }
                    THROW_NT_EXCEPTION(status, "BCryptDecrypt");
                }
            }
        }
    }
    CATCH_EXCEPTION;
}

// AES-GCM

CryptoAesGCMEncrypt::CryptoAesGCMEncrypt(
    CK_BBOOL type
) :
    CryptoEncrypt(type)
{}

CK_RV CryptoAesGCMEncrypt::Init
(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Object>    key
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        core::CryptoEncrypt::Init(
            pMechanism,
            key
        );

        if (!(key && key.get())) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "key is NULL");
        }
        auto castKey = dynamic_cast<AesKey*>(key.get());
        if (!castKey) {
            THROW_PKCS11_EXCEPTION(CKR_KEY_TYPE_INCONSISTENT, "Key must be AES");
        }
        this->key = castKey->GetKey()->Duplicate();

        if (pMechanism->mechanism != CKM_AES_GCM) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        // params
        if (pMechanism->pParameter == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "pMechanism->pParameter is NULL");
        }
        CK_AES_GCM_PARAMS_PTR params = static_cast<CK_AES_GCM_PARAMS_PTR>(pMechanism->pParameter);
        if (!params) {
            THROW_PKCS11_EXCEPTION(CKR_MECHANISM_PARAM_INVALID, "Cannot get CK_AES_GCM_PARAMS");
        }

        // IV
        iv = Scoped<std::string>(new std::string((PCHAR)params->pIv, params->ulIvLen));

        // AAD
        aad = Scoped<std::string>(new std::string(""));
        if (params->ulAADLen) {
            aad = Scoped<std::string>(new std::string((PCHAR)params->pAAD, params->ulAADLen));
        }

        // tagLength
        tagLength = params->ulTagBits >> 3;

        
        this->key->ChangeMode(BCRYPT_CHAIN_MODE_GCM);

        blockLength = this->key->GetNumber(BCRYPT_BLOCK_LENGTH);

        active = true;

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesGCMEncrypt::Once
(
    CK_BYTE_PTR       pData,
    CK_ULONG          ulDataLen,
    CK_BYTE_PTR       pEncryptedData,
    CK_ULONG_PTR      pulEncryptedDataLen
)
{
	LOGGER_FUNCTION_BEGIN;

    try {
        NTSTATUS status;
        Buffer tag(tagLength);

        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO authInfo;
        BCRYPT_INIT_AUTH_MODE_INFO(authInfo);
        authInfo.pbNonce = iv->length() ? (PUCHAR)iv->c_str() : NULL;
        authInfo.cbNonce = iv->length();
        authInfo.pbAuthData = aad->length() ? (PUCHAR)aad->c_str() : NULL;
        authInfo.cbAuthData = aad->length();
        authInfo.pbTag = tag.size() ? &tag[0] : NULL;
        authInfo.cbTag = tag.size();

        if (type == CRYPTO_ENCRYPT) {
            ULONG ulOutLen;

            // Get out data length
            status = BCryptEncrypt(key->Get(), pData, ulDataLen, &authInfo, NULL, 0, NULL, 0, &ulOutLen, 0);
            if (status) {
                active = false;
                THROW_NT_EXCEPTION(status, "BCryptEncrypt");
            }

            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulOutLen + tagLength;
            }
            else if (*pulEncryptedDataLen < ulOutLen + tagLength) {
                *pulEncryptedDataLen = ulOutLen + tagLength;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                if (tagLength) {
                    // Set pointer to tag block at the end of encrypted text
                    authInfo.cbTag = tagLength;
                    authInfo.pbTag = pEncryptedData + ulOutLen;
                }
                status = BCryptEncrypt(key->Get(), pData, ulDataLen, &authInfo, NULL, 0, pEncryptedData, ulOutLen, &ulOutLen, 0);
                *pulEncryptedDataLen = ulOutLen + tagLength;
                active = false;
                if (status) {
                    THROW_NT_EXCEPTION(status, "BCryptEncrypt");
                }
            }
        }
        else {
            ULONG ulOutLen;

            if (tagLength) {
                // Set pointer to tag block at the end of encrypted text
                authInfo.cbTag = tagLength;
                ulDataLen -= tagLength;
                authInfo.pbTag = pData + ulDataLen;
            }

            // Get out data length
            status = BCryptDecrypt(key->Get(), pData, ulDataLen, &authInfo, NULL, 0, NULL, 0, &ulOutLen, 0);
            if (status) {
                active = false;
                THROW_NT_EXCEPTION(status, "BCryptDecrypt");
            }

            if (pEncryptedData == NULL) {
                *pulEncryptedDataLen = ulOutLen;
            }
            else if (*pulEncryptedDataLen < ulOutLen) {
                *pulEncryptedDataLen = ulOutLen;
                THROW_PKCS11_BUFFER_TOO_SMALL();
            }
            else {
                status = BCryptDecrypt(key->Get(), pData, ulDataLen, &authInfo, NULL, 0, pEncryptedData, ulOutLen, &ulOutLen, 0);
                *pulEncryptedDataLen = ulOutLen;
                active = false;
                if (status) {
                    THROW_NT_EXCEPTION(status, "BCryptDecrypt");
                }
            }
        }
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV CryptoAesGCMEncrypt::Update
(
    CK_BYTE_PTR       pPart,
    CK_ULONG          ulPartLen,
    CK_BYTE_PTR       pEncryptedPart,
    CK_ULONG_PTR      pulEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    THROW_PKCS11_MECHANISM_INVALID();
}

CK_RV CryptoAesGCMEncrypt::Final
(
    CK_BYTE_PTR       pLastEncryptedPart,
    CK_ULONG_PTR      pulLastEncryptedPartLen
)
{
	LOGGER_FUNCTION_BEGIN;

    THROW_PKCS11_MECHANISM_INVALID();
}