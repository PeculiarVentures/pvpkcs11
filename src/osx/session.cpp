#include "session.h"

#include "../core/crypto.h"

#include "crypto.h"
#include "aes.h"

using namespace osx;

Scoped<core::Object> osx::Session::CreateObject
(
    CK_ATTRIBUTE_PTR        pTemplate,   /* the object's template */
    CK_ULONG                ulCount      /* attributes in template */
)
{
    try {
        core::Template tmpl(pTemplate, ulCount);
        
        Scoped<core::Object> object;
        switch (tmpl.GetNumber(CKA_CLASS, true)) {
            case CKO_SECRET_KEY:
                switch (tmpl.GetNumber(CKA_KEY_TYPE, true)) {
                    case CKK_AES:
                        object = Scoped<AesKey>(new AesKey());
                        break;
                    default:
                        THROW_PKCS11_TEMPLATE_INCOMPLETE();
                }
                break;
            default:
                THROW_PKCS11_TEMPLATE_INCOMPLETE();
        }
        
        object->CreateValues(pTemplate, ulCount);
        
        return object;
    }
    CATCH_EXCEPTION
}

Scoped<core::Object> osx::Session::CopyObject
(
    Scoped<core::Object>       object,      /* the object for copying */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new object */
    CK_ULONG             ulCount      /* attributes in template */
)
{
    try {

    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Open
(
    CK_FLAGS              flags,         /* from CK_SESSION_INFO */
    CK_VOID_PTR           pApplication,  /* passed to callback */
    CK_NOTIFY             Notify,        /* callback function */
    CK_SESSION_HANDLE_PTR phSession      /* gets session handle */
)
{
    try {
        core::Session::Open(
            flags,       
            pApplication,
            Notify,      
            phSession    
        );

        digest = Scoped<CryptoDigest>(new CryptoDigest());
        encrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_ENCRYPT));
        decrypt = Scoped<core::CryptoEncrypt>(new core::CryptoEncrypt(CRYPTO_DECRYPT));
        
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::Close()
{
    try {
        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::GenerateRandom(
    CK_BYTE_PTR       pPart,     /* data to be digested */
    CK_ULONG          ulPartLen  /* bytes of data to be digested */
) 
{
    try {
        core::Session::GenerateRandom(
            pPart,   
            ulPartLen
        );

        FILE *fp = fopen("/dev/random", "r");
        if (!fp) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Cannot get /dev/random");
        }
        
        for (int i=0; i<ulPartLen; i++) {
            pPart[i] = fgetc(fp);
        }
        
        fclose(fp);

        return CKR_OK;
    }
    CATCH_EXCEPTION
}

CK_RV osx::Session::GenerateKey
(
    CK_MECHANISM_PTR     pMechanism,  /* key generation mech. */
    CK_ATTRIBUTE_PTR     pTemplate,   /* template for new key */
    CK_ULONG             ulCount,     /* # of attrs in template */
    CK_OBJECT_HANDLE_PTR phKey        /* gets handle of new key */
)
{
    try {
        core::Session::GenerateKey(
            pMechanism,
            pTemplate,
            ulCount,
            phKey
        );

        Scoped<core::Template> tmpl(new core::Template(pTemplate, ulCount));

        Scoped<core::SecretKey> key;
        switch (pMechanism->mechanism) {
        case CKM_AES_KEY_GEN:
            key = AesKey::Generate(
                pMechanism,
                tmpl
            );
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        // add key to session's objects
        objects.add(key);

        // set handles for keys
        *phKey = key->handle;

        return CKR_OK;
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::EncryptInit
(
    CK_MECHANISM_PTR  pMechanism,  /* the encryption mechanism */
    CK_OBJECT_HANDLE  hKey         /* handle of encryption key */
)
{
    try {
        core::Session::EncryptInit(
            pMechanism,
            hKey
        );

        if (encrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_ECB:
            encrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_ENCRYPT));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return encrypt->Init(
            pMechanism,
            GetObject(hKey)
        );
    }
    CATCH_EXCEPTION;
}

CK_RV osx::Session::DecryptInit
(
    CK_MECHANISM_PTR  pMechanism,
    CK_OBJECT_HANDLE  hKey       
)
{
    try {
        core::Session::DecryptInit(
            pMechanism,
            hKey
        );

        if (decrypt->IsActive()) {
            THROW_PKCS11_OPERATION_ACTIVE();
        }

        switch (pMechanism->mechanism) {
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_ECB:
            decrypt = Scoped<CryptoAesEncrypt>(new CryptoAesEncrypt(CRYPTO_DECRYPT));
            break;
        default:
            THROW_PKCS11_MECHANISM_INVALID();
        }

        return decrypt->Init(
            pMechanism,
            GetObject(hKey)
        );
    }
    CATCH_EXCEPTION;
}
