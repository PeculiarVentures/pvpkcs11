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

    context("open", () => {

        it("wrong flag", () => {

            assert.throws(() => {
                mod.C_OpenSession(slot, 0);
            }, /CKR_SESSION_PARALLEL_NOT_SUPPORTED:180/);
        });

        it("read only", () => {

            const session = mod.C_OpenSession(slot, 4);
            const info = mod.C_GetSessionInfo(session);

            assert.equal(info.flags, 4);

            mod.C_CloseSession(session);
        });

        it("read/write", () => {

            const session = mod.C_OpenSession(slot, 6);
            const info = mod.C_GetSessionInfo(session);

            assert.equal(info.flags, 6);

            mod.C_CloseSession(session);
        });

    });

    context("Opened session", () => {
        let session;
        before(() => {
            session = mod.C_OpenSession(slot, 6);
        })

        after(() => {
            mod.C_CloseAllSessions(slot);
        })
        context("RNG", () => {
            it("generate random", () => {
                const buf = new Buffer(10);
                const hex1 = buf.toString("hex");
                const random = mod.C_GenerateRandom(session, buf);

                assert.equal(hex1 !== buf.toString("hex"), true);
                assert.equal(random.toString("hex"), buf.toString("hex"));
            });
            it("seed random", () => {
                assert.throws(() => {
                    const seed = mod.C_SeedRandom(session, new Buffer(10));
                }, /CKR_FUNCTION_NOT_SUPPORTED:84/);
            });
        });
    })

});