/// <reference types="mocha" />
const pkcs11 = require("pkcs11js");
const p11_crypto = require("node-webcrypto-p11");
const ossl_crypto = require("node-webcrypto-ossl");
const assert = require("assert");

const config = require("./config");

context("EC", () => {

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

    context("ossl vectors", () => {

        let p11, ossl;
        before(() => {
            p11 = new p11_crypto.WebCrypto({
                library: config.lib,
                slot: 0,
            });
            ossl = new ossl_crypto();
        })

        context("AES-CBC", () => {
            [
                128,
                192,
                256
            ].forEach((length) => {
                it(`${length}`, (done) => {
                    const alg = {
                        name: "AES-CBC",
                        length,
                        iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6])
                    }
                    const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]);
                    Promise.resolve()
                        .then(() => {
                            return p11.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
                                .then((key) => {
                                    return p11.subtle.exportKey("raw", key)
                                        .then((raw) => {
                                            return ossl.subtle.importKey("raw", raw, alg, true, ["encrypt", "decrypt"])
                                                .then((osslKey) => {
                                                    return ossl.subtle.encrypt(alg, osslKey, data);
                                                })
                                        })
                                        .then((enc) => {
                                            return p11.subtle.decrypt(alg, key, enc);
                                        })
                                        .then((dec) => {
                                            assert.equal(new Buffer(dec).toString("hex"), data.toString("hex"));
                                        });
                                });
                        })
                        .then(done, done);
                })
            });
        });
        
        context("AES-ECB", () => {
            [
                128,
                192,
                256
            ].forEach((length) => {
                it(`${length}`, (done) => {
                    const alg = {
                        name: "AES-ECB",
                        length,
                    }
                    const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5]);
                    Promise.resolve()
                        .then(() => {
                            return p11.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
                                .then((key) => {
                                    return p11.subtle.exportKey("raw", key)
                                        .then((raw) => {
                                            return ossl.subtle.importKey("raw", raw, alg, true, ["encrypt", "decrypt"])
                                                .then((osslKey) => {
                                                    return ossl.subtle.encrypt(alg, osslKey, data);
                                                })
                                        })
                                        .then((enc) => {
                                            return p11.subtle.decrypt(alg, key, enc);
                                        })
                                        .then((dec) => {
                                            assert.equal(new Buffer(dec).toString("hex"), data.toString("hex"));
                                        });
                                });
                        })
                        .then(done, done);
                })
            });
        });

    })

});