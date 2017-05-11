/// <reference types="mocha" />
const pkcs11 = require("pkcs11js");
const p11_crypto = require("node-webcrypto-p11");
const ossl_crypto = require("node-webcrypto-ossl");
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
                { type: pkcs11.CKA_PUBLIC_EXPONENT, value: new Buffer([1, 0, 1]) },
                { type: pkcs11.CKA_MODULUS_BITS, value: 1024 },
                { type: pkcs11.CKA_VERIFY, value: true },
            ];

            const keys = mod.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_RSA_PKCS_KEY_PAIR_GEN, parameter: null }, publicTemplate, privateTemplate);

            privateKey = keys.privateKey;
            publicKey = keys.publicKey;
        });

        context("RSA-PKCS1", () => {
            [
                "CKM_SHA1_RSA_PKCS",
                "CKM_SHA256_RSA_PKCS",
                "CKM_SHA384_RSA_PKCS",
                "CKM_SHA512_RSA_PKCS"
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
        context("RSA-PSS", () => {
            [
                "CKM_SHA1_RSA_PKCS_PSS",
                "CKM_SHA256_RSA_PKCS_PSS",
                "CKM_SHA384_RSA_PKCS_PSS",
                "CKM_SHA512_RSA_PKCS_PSS"
            ]
                .forEach((mech) => {
                    it(mech, () => {
                        const parameter = {
                            hashAlg: pkcs11.CKM_SHA_1,
                            mgf: pkcs11.CKG_MGF1_SHA1,
                            saltLen: 12,
                            type: pkcs11.CK_PARAMS_RSA_PSS
                        };

                        const mechanism = { mechanism: pkcs11[mech], parameter };

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
            ossl = new ossl_crypto();
        })

        context("sign/verify", () => {

            context("RSASSA-PKCS1-v1_5", () => {

                [
                    "SHA-1",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512",
                ].forEach((hash) => {
                    it(hash, (done) => {
                        const alg = {
                            name: "RSASSA-PKCS1-v1_5",
                            publicExponent: new Uint8Array([1, 0, 1]),
                            modulusLength: 2048,
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

            context("RSA-PSS", () => {

                [
                    "SHA-1",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512",
                ].forEach((hash) => {
                    it(hash, (done) => {
                        const alg = {
                            name: "RSA-PSS",
                            publicExponent: new Uint8Array([1, 0, 1]),
                            modulusLength: 2048,
                            hash,
                            saltLength: 64
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

            context("RSA-OAEP", () => {
                [
                    "SHA-1",
                    "SHA-256",
                    "SHA-384",
                    "SHA-512",
                ].forEach((hash) => {
                    it(hash, (done) => {
                        const alg = {
                            name: "RSA-OAEP",
                            hash,
                            publicExponent: new Uint8Array([1, 0, 1]),
                            modulusLength: 2048,
                            label: new Buffer("label value") 
                        };
                        const data = new Buffer("Test data");
                        Promise.resolve()
                            .then(() => {
                                return p11.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
                                    .then((keys) => {
                                        return p11.subtle.exportKey("spki", keys.publicKey)
                                            .then((spki) => {
                                                return ossl.subtle.importKey("spki", spki, alg, true, ["encrypt"]);
                                            })
                                            .then((publicKey) => {
                                                return ossl.subtle.encrypt(alg, publicKey, data);
                                            })
                                            .then((enc) => {
                                                return p11.subtle.decrypt(alg, keys.privateKey, enc);
                                            })
                                            .then((dec) => {
                                                assert.equal(new Buffer(dec).toString(), data.toString());
                                            })
                                    })
                            })
                            .then(done, done);
                    })
                })
            })

        });
    })

});