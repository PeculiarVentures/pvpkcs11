/// <reference types="mocha" />

// @ts-check

const pkcs11 = require("pkcs11js");
const p11_crypto = require("node-webcrypto-p11");
const ossl_crypto = require("node-webcrypto-ossl");
const assert = require("assert");

const config = require("./test/config");


let p11 = new p11_crypto.WebCrypto({
    library: config.lib,
    slot: 0,
});
let ossl = new ossl_crypto();

const alg = {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
};

const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);

p11.subtle.generateKey(alg, true, ["sign", "verify"])
    .then((k) => {
        return p11.subtle.sign(alg, k.privateKey, data)
            .then((signature) => {
                return p11.subtle.exportKey("jwk", k.publicKey)
                    .then((raw) => {
                        console.log(raw);
                        return ossl.subtle.importKey("jwk", raw, alg, true, ["verify"]);
                    })
                    .then((osslKey) => {
                        return ossl.subtle.verify(alg, osslKey, signature, data)
                            .then((ok) => {
                                console.log("Signature:", ok);
                            })
                    })
            })
    })
    // @ts-ignore
    .catch((err) => {
        console.error(err);
    })
