/// <reference types="mocha" />

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
    hash: "SHA-1"
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
    // @ts-ignore
    .catch((e) => {
        console.error(e);
    })