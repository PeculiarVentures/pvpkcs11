#include "slot.h"
#include "session.h"

using namespace osx;

#define OSX_SLOT_NAME "MacOS Crypto"
#define MANUFACTURER_ID "Peculiar Ventures"

osx::Slot::Slot() :
    core::Slot()
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        SET_STRING(this->manufacturerID, MANUFACTURER_ID, 32);
        SET_STRING(this->description, OSX_SLOT_NAME, 64);
        this->flags = CKF_TOKEN_INITIALIZED | CKF_RNG;
        this->hardwareVersion.major = 0;
        this->hardwareVersion.minor = 1;
        this->firmwareVersion.major = 0;
        this->firmwareVersion.minor = 1;

        // Token info
        SET_STRING(this->tokenInfo.label, OSX_SLOT_NAME, 32);
        SET_STRING(this->tokenInfo.manufacturerID, MANUFACTURER_ID, 32);
        SET_STRING(this->tokenInfo.serialNumber, "1", 16);
        this->tokenInfo.hardwareVersion.major = 0;
        this->tokenInfo.hardwareVersion.minor = 1;
        this->tokenInfo.firmwareVersion.major = 0;
        this->tokenInfo.firmwareVersion.minor = 1;

        // Add mechanisms
        //   SHA
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA_1, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384, 0, 0, CKF_DIGEST)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512, 0, 0, CKF_DIGEST)));
        //   RSA
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_RSA_PKCS_KEY_PAIR_GEN, 1024, 4096, CKF_GENERATE)));
        //      PKCS1
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA1_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512_RSA_PKCS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        /*
        //      PSS
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA1_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA256_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA384_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_SHA512_RSA_PKCS_PSS, 1024, 4096, CKF_SIGN | CKF_VERIFY)));
        //      OAEP
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_RSA_PKCS_OAEP, 1024, 4096, CKF_ENCRYPT | CKF_DECRYPT)));
         */
        //   EC
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_KEY_PAIR_GEN, 256, 521, CKF_GENERATE)));
        //      ECDSA
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA1, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA256, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA384, 256, 521, CKF_SIGN | CKF_VERIFY)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDSA_SHA512, 256, 521, CKF_SIGN | CKF_VERIFY)));
        
        /*
         */
        //      ECDH
        // this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_ECDH1_DERIVE, 256, 521, CKF_DERIVE)));
        //   AES
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_KEY_GEN, 128, 256, CKF_GENERATE)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_CBC_PAD, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_CBC, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_ECB, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
        this->mechanisms.add(Scoped<core::Mechanism>(new core::Mechanism(CKM_AES_GCM, 128, 256, CKF_ENCRYPT | CKF_DECRYPT)));
    }
    CATCH_EXCEPTION;
}

Scoped<core::Session> osx::Slot::CreateSession()
{
    LOGGER_FUNCTION_BEGIN;
    
    try {
        return Scoped<Session>(new Session());
    }
    CATCH_EXCEPTION;
}
