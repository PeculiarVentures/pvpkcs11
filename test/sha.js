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

    context("SHA", () => {
        it("SHA-1", () => {
            mod.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA_1, parameter: null });

            mod.C_DigestUpdate(session, new Buffer("first"));
            mod.C_DigestUpdate(session, new Buffer("second"));

            const digest = mod.C_DigestFinal(session, new Buffer(256));

            assert.strictEqual("47f7d821cad2070ebef455e5d0506d6d944bb2cb", digest.toString("hex"));
        });
        it("SHA-1 once", () => {
            mod.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA_1, parameter: null });

            const digest = mod.C_Digest(session, new Buffer("firstsecond"), new Buffer(256));

            assert.strictEqual("47f7d821cad2070ebef455e5d0506d6d944bb2cb", digest.toString("hex"));
        });
        it("SHA-256", () => {
            mod.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA256, parameter: null });

            mod.C_DigestUpdate(session, new Buffer("first"));
            mod.C_DigestUpdate(session, new Buffer("second"));

            const digest = mod.C_DigestFinal(session, new Buffer(256));

            assert.strictEqual("da83f63e1a473003712c18f5afc5a79044221943d1083c7c5a7ac7236d85e8d2", digest.toString("hex"));
        });
        it("SHA-384", () => {
            mod.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA384, parameter: null });

            mod.C_DigestUpdate(session, new Buffer("first"));
            mod.C_DigestUpdate(session, new Buffer("second"));

            const digest = mod.C_DigestFinal(session, new Buffer(256));

            assert.strictEqual("c4b4e9a273c652c9c698f4f130cb441274621616b84b58def8e9005c66429af37cb92b036b254d4950025db71447831f", digest.toString("hex"));
        });
        it("SHA-512", () => {
            mod.C_DigestInit(session, { mechanism: pkcs11.CKM_SHA512, parameter: null });

            mod.C_DigestUpdate(session, new Buffer("first"));
            mod.C_DigestUpdate(session, new Buffer("second"));

            const digest = mod.C_DigestFinal(session, new Buffer(256));

            assert.strictEqual("3829d8caf2228a6b972ac84802618160666aed4d346d6d152956c42aa49d5ccac0c26744494bf9f230ea8fd11610889ce8989f0a0899d125beeddd46c23c624e", digest.toString("hex"));
        });
    })

});