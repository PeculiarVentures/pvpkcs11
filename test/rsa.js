/// <reference types="mocha" />
const pkcs11 = require("pkcs11js");
const assert = require("assert");

const config = require("./config");

context("RSA", () => {

    let mod = new pkcs11.PKCS11();;
    let slot, session;

    before(() => {
        mod.load(config.lib);
        mod.C_Initialize();
        const slots = mod.C_GetSlotList();
        slot = slots[0];
        session = mod.C_OpenSession(slot, pkcs11.CKF_RW_SESSION | pkcs11.CKF_SERIAL_SESSION);
    });

    after(() => {
        mod.C_CloseAllSessions(slot);
        mod.C_Finalize();
    });

    context("GenerateKeyPair", () => {
        it("#1", () => {
            const privateTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_SIGN, value: true },
                { type: pkcs11.CKA_DECRYPT, value: true },
                { type: pkcs11.CKA_UNWRAP, value: true },
            ];
            const publicTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: new Buffer([1, 0, 1]) },
                { type: pkcs11.CKA_MODULUS_BITS, value: 1024 },
                { type: pkcs11.CKA_VERIFY, value: true },
                { type: pkcs11.CKA_ENCRYPT, value: true },
                { type: pkcs11.CKA_WRAP, value: true },
            ];

            const keys = mod.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, parameter: null }, publicTemplate, privateTemplate);
            console.log(keys);

            let attrs = mod.C_GetAttributeValue(session, keys.privateKey, [
                {type: pkcs11.CKA_TOKEN }
            ]);

            console.log(attrs);
        });
    })

});