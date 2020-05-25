/// <reference types="mocha" />
const pkcs11 = require("pkcs11js");
const p11_crypto = require("node-webcrypto-p11");
const { Crypto } = require("@peculiar/webcrypto");
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

    context("GenerateKeyPair", () => {
        it("#1", () => {
            const privateTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_SIGN, value: true },
                { type: pkcs11.CKA_DERIVE, value: true },
            ];
            const publicTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_EC_PARAMS, value: new Buffer("06082A8648CE3D030107", "hex") },
                { type: pkcs11.CKA_VERIFY, value: true },
                { type: pkcs11.CKA_DERIVE, value: true },
            ];

            const keys = mod.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_ECDSA_KEY_PAIR_GEN, parameter: null }, publicTemplate, privateTemplate);

            let attrs = mod.C_GetAttributeValue(session, keys.privateKey, [
                { type: pkcs11.CKA_TOKEN }
            ]);
        });
    });

    context("Sign/Verify", () => {
        let privateKey, publicKey;

        before(() => {
            const privateTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_SIGN, value: true },
            ];
            const publicTemplate = [
                { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
                { type: pkcs11.CKA_EC_PARAMS, value: new Buffer("06082A8648CE3D030107", "hex") },
                { type: pkcs11.CKA_VERIFY, value: true },
            ];

            const keys = mod.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_ECDSA_KEY_PAIR_GEN, parameter: null }, publicTemplate, privateTemplate);

            privateKey = keys.privateKey;
            publicKey = keys.publicKey;
        });

        context("ECDSA", () => {
            [
                "CKM_ECDSA_SHA1",
                "CKM_ECDSA_SHA256",
                "CKM_ECDSA_SHA384",
                "CKM_ECDSA_SHA512",
            ]
                .forEach((mech) => {
                    it(mech, () => {
                        const mechanism = { mechanism: pkcs11[mech], parameter: null };

                        mod.C_SignInit(session, mechanism, privateKey);

                        mod.C_SignUpdate(session, new Buffer("first"));
                        mod.C_SignUpdate(session, new Buffer("second"));

                        const signature = mod.C_SignFinal(session, new Buffer(1024));

                        mod.C_VerifyInit(session, mechanism, publicKey);

                        mod.C_VerifyUpdate(session, new Buffer("first"));
                        mod.C_VerifyUpdate(session, new Buffer("second"));

                        const res = mod.C_VerifyFinal(session, signature);
                        assert.equal(res, true);
                    });
                });
        });
    });

    context("ossl vectors", () => {
        let p11, ossl;
        before(() => {
            p11 = new p11_crypto.WebCrypto({
                library: config.lib,
                slot: 0,
            });
            ossl = new Crypto();
        })

        context("sign/verify", () => {

            context("ECDSA", () => {

                [
                    "SHA-1",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512",
                ].forEach((hash) => {
                    it(hash, (done) => {
                        const alg = {
                            name: "ECDSA",
                            namedCurve: "P-256",
                            hash
                        };
                        const data = new Buffer("Test data");
                        p11.subtle.generateKey(alg, true, ["sign", "verify"])
                            .then((keys) => {
                                return p11.subtle.exportKey("jwk", keys.publicKey)
                                    .then((jwk) => {
                                        // console.log(jwk);
                                        return ossl.subtle.importKey("jwk", jwk, alg, true, ["verify"])
                                    })
                                    .then((publicKey) => {
                                        return p11.subtle.sign(alg, keys.privateKey, data)
                                            .then((signature) => {
                                                return ossl.subtle.verify(alg, publicKey, signature, data);
                                            })
                                            .then((ok) => {
                                                assert.equal(ok, true);
                                            })
                                    })
                            })
                            .then(done, done);
                    })
                });
            });

        });
    });

});