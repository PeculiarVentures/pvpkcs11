/// <reference types="mocha" />

const pkcs11 = require("pkcs11js");
const assert = require("assert");

const config = require("./config");

context("Slot", () => {

    let mod = new pkcs11.PKCS11();;
    let slot;

    before(() => {
        mod.load(config.lib);
        mod.C_Initialize();
        const slots = mod.C_GetSlotList();
        slot = slots[0];
    });

    after(() => {
        mod.C_Finalize();
    });

    it("Info", () => {
        const info = mod.C_GetSlotInfo(slot);

        assert.equal(info.slotDescription, "Windows CryptoAPI                                               ");
        assert.equal(info.manufacturerID, "Windows CryptoAPI               ");
        assert.equal(info.flags, 1025);
    });

    context("Mechanism", () => {
        
        it("get list", () => {
            const mechanisms = mod.C_GetMechanismList(slot);
            assert.equal(mechanisms.length > 0, true);
        });

        it("get info", () => {
            const info = mod.C_GetMechanismInfo(slot, 6);

            assert.equal(info.minKeySize, 1024);
            assert.equal(info.maxKeySize, 4096);
            assert.equal(info.flags, 10240);
        });

    });

});