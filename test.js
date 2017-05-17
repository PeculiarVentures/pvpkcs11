/// <reference types="mocha" />

// @ts-check

const pkcs11 = require("pkcs11js");
const helper = require("pvtsutils");
const p11_crypto = require("node-webcrypto-p11");
const ossl_crypto = require("node-webcrypto-ossl");
const assert = require("assert");

const config = require("./test/config");


let p11 = new p11_crypto.WebCrypto({
    library: config.lib,
    slot: 0,
});
let ossl = new ossl_crypto();

// const alg = {
//     name: "RSASSA-PKCS1-v1_5",
//     hash: "SHA-256",
//     publicExponent: new Uint8Array([1, 0, 1]),
//     modulusLength: 1024,
// };
const alg = {
    name: "ECDSA",
    namedCurve: "P-256",
    hash: "SHA-256",
};
// const alg = {
//     name: "AES-CBC",
//     length: 256
// };

const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);

function hex2b64url(hex) {
    return helper.Convert.ToBase64Url(helper.Convert.FromHex(hex));
}

p11.subtle.generateKey(alg, true, ["sign", "verify"])
    .then((keys) => {
        return p11.subtle.exportKey("jwk", keys.publicKey)
            .then((jwk) => {
                console.log(jwk);
                return p11.subtle.importKey("jwk", jwk, alg, true, ["verify"])
            })
            .then((importedKey) => {
                console.log("Success");
                // console.log(importedKey);
                return p11.subtle.exportKey("jwk", importedKey);
            })
            .then((jwk) => {
                console.log(jwk);
            })
        // Sign
        // .then(() => {
        //     return p11.subtle.sign(alg, keys.privateKey, data)
        // })
        // .then((signature) => {
        //     return p11.subtle.verify(alg, keys.publicKey, signature, data)
        // })
        // .then((ok) => {
        //     console.log(ok);
        // })
    })
    // @ts-ignore
    .catch((err) => {
        console.error(err);
    });
