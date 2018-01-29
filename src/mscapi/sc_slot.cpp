#include "sc_slot.h"
#include "sc_session.h"

using namespace mscapi;

const char * MS_SMART_CARD_MANUFACTURIER_ID = "MS SmartCard Provider";

mscapi::SmartCardSlot::SmartCardSlot(
    PCCH        readerName,
    PCCH        provName,
    DWORD       provType
) :
    core::Slot(),
    readerName(Scoped<std::string>(new std::string(readerName))),
    provName(Scoped<std::string>(new std::string(provName))),
    provType(provType)
{
    LOGGER_FUNCTION_BEGIN;

    try {
#pragma region Slot info
        SET_STRING(this->manufacturerID, provName, 32);
        SET_STRING(this->description, readerName, 64);
        this->flags = CKF_TOKEN_INITIALIZED | CKF_RNG | CKF_REMOVABLE_DEVICE;
        this->hardwareVersion = { 0, 1 };
        this->firmwareVersion = { 0, 1 };
#pragma endregion

#pragma region Token info
        SET_STRING(this->tokenInfo.label, readerName, 32);
#pragma endregion

#pragma region Mechanisms
#pragma region SHA digest
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA_1, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512, 0, 0, CKF_DIGEST)));
#pragma endregion
#pragma region RSA
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, 1024, 4096, CKF_GENERATE)));
        // PKCS1
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA1_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        // PSS
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA1_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        // OAEP
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_RSA_PKCS_OAEP, 1024, 4096, CKF_ENCRYPT | CKF_DECRYPT)));
#pragma endregion
#pragma region EC
        // ECDSA
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA1, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA256, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA384, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA512, 256, 521, CKF_SIGN | CKF_VERIFY)));
        // ECDH
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDH1_DERIVE, 256, 521, CKF_DERIVE)));
#pragma endregion
#pragma region AES
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_KEY_GEN, 128, 256, CKF_GENERATE)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_CBC, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_CBC_PAD, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_ECB, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_GCM, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
#pragma endregion
#pragma endregion

    }
    CATCH_EXCEPTION
}

Scoped<core::Session> mscapi::SmartCardSlot::CreateSession()
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        return Scoped<core::Session>(new SmartCardSession(
            readerName->c_str(), 
            provName->c_str(), 
            provType
        ));
    }
    CATCH_EXCEPTION;
}