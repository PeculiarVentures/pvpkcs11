/// <reference types="mocha" />
const pkcs11 = require("pkcs11js");
const assert = require("assert");

const config = require("./config");

context("Module", () => {

    it("Initialize", () => {
        const mod = new pkcs11.PKCS11();
        mod.load(config.lib);

        mod.C_Initialize();

        mod.C_Finalize();
    });

    it("Call function without module initialization ", () => {
        const mod = new pkcs11.PKCS11();
        mod.load(config.lib);

        assert.throws(() => {
            mod.C_GetInfo();
        }, /CKR_CRYPTOKI_NOT_INITIALIZED:400/);
    });

    context("Methods", () => {

        let mod = new pkcs11.PKCS11();;

        before(() => {
            mod.load(config.lib);
            mod.C_Initialize();
        });

        after(() => {
            mod.C_Finalize();
        });

        it("Info", () => {
            const info = mod.C_GetInfo();

            assert.strictEqual(info.cryptokiVersion.major, 2);
            assert.strictEqual(info.cryptokiVersion.minor, 30);
            assert.strictEqual(info.manufacturerID, "Module                          ");
            assert.strictEqual(info.flags, 0);
            assert.strictEqual(info.libraryDescription, "Windows CryptoAPI               ");
            assert.strictEqual(info.libraryVersion.major, 0);
            assert.strictEqual(info.libraryVersion.minor, 1);
        });

        it("GetSlots", () => {
            assert.strictEqual(mod.C_GetSlotList().length, 1);
        });

        it("GetSlotInfo wrong index", () => {
            assert.throws(() => {
                mod.C_GetSlotInfo(new Buffer([1,2,3,4,5,6,7,8]));
            }, /CKR_SLOT_ID_INVALID:3/);
        });

    })



});