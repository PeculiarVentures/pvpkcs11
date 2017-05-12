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
    name: "AES-GCM",
    length: 128,
    iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2]),
    additionalData: new Buffer([1, 2, 3, 4, 5, 6]),
    tagLength: 128,
};

const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0]);

p11.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
    .then((k) => {
        return p11.subtle.exportKey("raw", k)
            .then((raw) => {
                console.log(new Uint8Array(raw));
                return ossl.subtle.importKey("raw", raw, alg, true, ["encrypt", "decrypt"]);
            })
            .then((osslKey) => {
                return ossl.subtle.encrypt(alg, osslKey, data)
                    .then((enc) => {
                        enc = new Buffer(enc)
                        console.log(enc.toString("hex"));
                        return p11.subtle.encrypt(alg, k, data);
                    })
                    .then((enc) => {
                        enc = new Buffer(enc)
                        console.log(enc.toString("hex"));
                        return p11.subtle.decrypt(alg, k, enc);
                    })
                    .then((dec) => {
                        console.log(new Buffer(dec).toString("hex"));
                        return p11.subtle.encrypt(alg, k, new Buffer([]));
                    })
            })
    })
    // @ts-ignore
    .catch((err) => {
        console.error(err);
    })
