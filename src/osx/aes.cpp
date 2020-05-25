#include "aes.h"

#include <CommonCrypto/CommonCrypto.h>
#include <Security/Security.h>
#include <CoreFoundation/CoreFoundation.h>

using namespace osx;

Scoped<Buffer> GenerateRandom(CK_ULONG size)
{
    try {
        FILE *fp = fopen("/dev/random", "r");
        if (!fp) {
            THROW_PKCS11_EXCEPTION(CKR_FUNCTION_FAILED, "Cannot get /dev/random");
        }
        
        Scoped<Buffer> buffer(new Buffer(size));
        for (int i=0; i<size; i++) {
            buffer->at(i) = fgetc(fp);
        }
        
        fclose(fp);
        
        return buffer;
        
    }
    CATCH_EXCEPTION
}

Scoped<core::SecretKey> osx::AesKey::Generate(
    CK_MECHANISM_PTR        pMechanism,
    Scoped<core::Template>  tmpl
)
{
    try {
        if (pMechanism == NULL_PTR) {
            THROW_PKCS11_EXCEPTION(CKR_ARGUMENTS_BAD, "pMechanism is NULL");
        }
        if (pMechanism->mechanism != CKM_AES_KEY_GEN) {
            THROW_PKCS11_MECHANISM_INVALID();
        }

        Scoped<AesKey> aesKey(new AesKey());
        // check template in core
        aesKey->GenerateValues(tmpl->Get(), tmpl->Size());

        CK_ULONG ulKeyLength = tmpl->GetNumber(CKA_VALUE_LEN, true, 0);

        // check CKA_VALUE_LEN
        switch (ulKeyLength) {
            case 16:
            case 24:
            case 32:
                break;
            default:
                THROW_PKCS11_EXCEPTION(CKR_ATTRIBUTE_VALUE_INVALID, "CKA_VALUE must be 16, 24 or 32");
        }

        // Generate random data for symmetric key
        Scoped<Buffer> buffer = GenerateRandom(ulKeyLength);
                  
        aesKey->ItemByType(CKA_VALUE)->To<core::AttributeBytes>()->Set(buffer->data(), buffer->size());

        return aesKey;
    }   
    CATCH_EXCEPTION
}

osx::AesKey::~AesKey()
{
}

CK_RV osx::AesKey::CreateValues(
    CK_ATTRIBUTE_PTR  pTemplate,  /* specifies attributes */
    CK_ULONG          ulCount     /* attributes in template */
)
{
    try {
        core::Template tmpl(pTemplate, ulCount);
        core::AesKey::CreateValues(pTemplate, ulCount);
        

        Scoped<Buffer> value = tmpl.GetBytes(CKA_VALUE, true, "");
        switch (value->size()) {
        case 16:
        case 24:
        case 32:
            break;
        default:
            THROW_PKCS11_EXCEPTION(CKR_TEMPLATE_INCONSISTENT, "Wrong size for AES key. Must be 16, 24 or 32");
        }
        
        ItemByType(CKA_VALUE)->SetValue(value->data(), value->size());
        
        return CKR_OK;
    }   
    CATCH_EXCEPTION
}

CK_RV osx::AesKey::Destroy()
{
    try {
        return CKR_OK;
    }   
    CATCH_EXCEPTION
}
