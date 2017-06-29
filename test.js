// @ts-check

const { WebCrypto } = require("node-webcrypto-p11");
const ossl = new (require("node-webcrypto-ossl"));
const crypto = new WebCrypto({
    library: "out/Debug_x64/libpvpkcs11.dylib",
    slot: 0,
})
// const crypto = ossl;

Promise.resolve()
    .then(() => {
        return TestEcDerive();
    })
    .catch((err) => {
        console.error(err);
    })

function TestAES() {
    // const alg = { name: "AES-CBC", length: 128, iv: new Uint8Array([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]) };
    const alg = { name: "AES-ECB", length: 128 };
    // const data = new Buffer("Some data for encryption");
    const data = new Buffer("12345678901234561234567890123456");
    return crypto.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
        .then((key) => {
            return crypto.subtle.encrypt(alg, key, data)
                .then((enc) => {
                    console.log("Encrypted:", new Buffer(enc).toString("hex"));
                    return crypto.subtle.decrypt(alg, key, enc);
                })
                .then((dec) => {
                    console.log("Decrypted:", new Buffer(dec).toString("utf8"));
                })
                .then(() => {
                    return crypto.subtle.exportKey("raw", key);
                })
                .then((raw) => {
                    console.log("import");
                    return ossl.subtle.importKey("raw", raw, alg, true, ["encrypt", "decrypt"]);
                })
                .then((osslKey) => {
                    return ossl.subtle.encrypt(alg, osslKey, data)
                        .then((enc) => {
                            console.log("Encrypted:", new Buffer(enc).toString("hex"));
                            return ossl.subtle.decrypt(alg, osslKey, enc);
                        })
                        .then((dec) => {
                            console.log("Decrypted:", new Buffer(dec).toString("utf8"));
                        })
                })
        })
}
function TestAES_GCM() {
    const alg = {
        name: "AES-GCM",
        length: 256,
        additionaData: new Buffer("1234567890"),
        iv: new Buffer("123456789012"),
        tagLength: 0
    };
    const data = new Buffer("12345678901234561234567890123456");
    return crypto.subtle.generateKey(alg, true, ["encrypt", "decrypt"])
        .then((key) => {
            return crypto.subtle.encrypt(alg, key, data)
                .then((enc) => {
                    console.log("Encrypted:", new Buffer(enc).toString("hex"));
                    return crypto.subtle.decrypt(alg, key, enc);
                })
                .then((dec) => {
                    console.log("Decrypted:", new Buffer(dec).toString("utf8"));
                })
                .then(() => {
                    return crypto.subtle.exportKey("raw", key);
                })
                .then((raw) => {
                    console.log("import");
                    return ossl.subtle.importKey("raw", raw, alg, true, ["encrypt", "decrypt"]);
                })
                .then((osslKey) => {
                    return ossl.subtle.encrypt(alg, osslKey, data)
                        .then((enc) => {
                            console.log("Encrypted:", new Buffer(enc).toString("hex"));
                            return ossl.subtle.decrypt(alg, osslKey, enc);
                        })
                        .then((dec) => {
                            console.log("Decrypted:", new Buffer(dec).toString("utf8"));
                        })
                })
        })
}

function TestCertList() {
    return crypto.keyStorage.keys()
        .then((indexes) => {
            console.log("Keys:", indexes);
        })
        .then(() => {
            return crypto.certStorage.keys()
                .then((indexes) => {
                    console.log("Certificates:", indexes);
                    //         const promises = [];
                    //         for (let i = 0; i < indexes.length; i++) {
                    //             promises.push(
                    //                 crypto.certStorage.getItem(indexes[i])
                    //                     .then((cert) => {
                    //                         // @ts-ignore
                    //                         console.log(cert.toJSON());
                    //                     })
                    //             )
                    //         }
                    //         return Promise.all(promises);
                })
        })
}

function TestSign() {
    const alg = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
    const data = new Buffer("test");
    return Promise.resolve()
        .then(() => {
            return crypto.keyStorage.keys();
        })
        .then((indexes) => {
            for (const index of indexes) {
                const parts = index.split("-");
                if (parts[0] === "private") {
                    return crypto.keyStorage.getItem(index);
                }
            }
        })
        .then((key) => {
            return crypto.subtle.sign(alg, key, data)
                .then((signature) => {
                    console.log("signature:", new Buffer(signature).toString("hex"));
                    return crypto.keyStorage.indexOf(key)
                        .then((index) => {
                            // get public key by private key index
                            const parts = index.split("-");
                            return crypto.keyStorage.keys()
                                .then((indexes) => {
                                    for (const index of indexes) {
                                        if (/public/.test(index) && index.indexOf(parts[2]) !== 0) {
                                            return crypto.keyStorage.getItem(index);
                                        }
                                    }
                                })
                        })
                        .then((key) => {
                            return crypto.subtle.verify(alg, key, signature, data);
                        })
                        .then((ok) => {
                            console.log("Signature:", ok);
                        })
                })
                .then(() => {
                    return crypto.subtle.exportKey("jwk", key)
                })
                .then((jwk) => {
                    console.log(jwk);
                })
        })
}

function TestECGenerate() {
    const alg = { name: "ECDSA", hash: "SHA-256", namedCurve: "P-521" };

    return Promise.resolve()
        .then(() => {
            return crypto.subtle.generateKey(alg, true, ["sign", "verify"])
                .then((keys) => {
                    console.log("Keys:", keys);
                    return crypto.subtle.exportKey("jwk", keys.privateKey)
                        .then((jwk) => {
                            console.log(jwk);
                            return crypto.subtle.exportKey("jwk", keys.publicKey)
                        })
                        .then((jwk) => {
                            console.log(jwk);
                            // @ts-ignore
                            return ossl.subtle.importKey("jwk", jwk, keys.publicKey.algorithm, false, ["verify"])
                                .then(() => {
                                })
                        })
                })
        })
}

function TestEcSign() {
    const alg = { name: "ECDSA", hash: "SHA-512", namedCurve: "P-521" };
    const data = new Buffer("Some data");

    return Promise.resolve()
        .then(() => {
            return crypto.subtle.generateKey(alg, true, ["sign", "verify"])
                .then((keys) => {
                    return crypto.subtle.sign(alg, keys.privateKey, data)
                        .then((signature) => {
                            console.log("signature:", new Buffer(signature).toString("hex"));
                            // return crypto.subtle.verify(alg, keys.publicKey, signature, data);
                            return crypto.subtle.exportKey("jwk", keys.publicKey)
                                .then((jwk) => {
                                    return ossl.subtle.importKey("jwk", jwk, alg, true, ["verify"])
                                })
                                .then((key) => {
                                    return ossl.subtle.verify(alg, key, signature, data);
                                })
                        })
                        .then((ok) => {
                            console.log("signature:", ok);
                        })
                })
        })
}
function TestEcDerive() {
    const alg = { name: "ECDH", namedCurve: "P-256" };

    return Promise.resolve()
        .then(() => {
            return crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"])
                .then((keys) => {
                    return crypto.subtle.exportKey("jwk", keys.publicKey)
                        .then((jwk) => {
                            return ossl.subtle.importKey("jwk", jwk, alg, true, ["deriveBits"])
                                .then((osslPublicKey) => {
                                    return crypto.subtle.exportKey("jwk", keys.privateKey)
                                        .then((jwk2) => {
                                            jwk2.x = jwk.x;
                                            jwk2.y = jwk.y;
                                            console.log(jwk, jwk2);
                                            return ossl.subtle.importKey("jwk", jwk2, alg, true, ["deriveBits"])
                                        })
                                        .then((osslPrivateKey) => {
                                            return ossl.subtle.deriveBits({
                                                name: "ECDH",
                                                public: osslPublicKey
                                            },
                                                osslPrivateKey,
                                                128)
                                                .then((data) => {
                                                    console.log(`Derived:\n${new Buffer(data).toString("hex")}`);
                                                    return ossl.subtle.exportKey("jwk", osslPublicKey)
                                                        .then((jwk) => {
                                                            // console.log(jwk);
                                                            return ossl.subtle.exportKey("jwk", osslPrivateKey)
                                                                .then((jwk) => {
                                                                    // console.log(jwk);
                                                                })
                                                        })
                                                })
                                        })
                                })
                        })
                        .then(() => {
                            return crypto.subtle.deriveBits({
                                name: "ECDH",
                                public: keys.publicKey
                            },
                                keys.privateKey,
                                128);
                        })
                })
                .then((data) => {
                    console.log("Derived:", new Buffer(data).toString("hex"));
                })
        })
}
function TestEcExportPublic() {
    const alg = { name: "ECDH", namedCurve: "P-521" };

    return Promise.resolve()
        .then(() => {
            return crypto.subtle.generateKey(alg, true, ["deriveBits", "deriveKey"])
                .then((keys) => {
                    return crypto.subtle.exportKey("jwk", keys.publicKey)
                        .then((jwk) => {
                            console.log(jwk);
                            return crypto.subtle.importKey("jwk", jwk, alg, true, ["deriveBits"])
                                .then((key) => {
                                    return crypto.subtle.exportKey("jwk", key)
                                })
                                .then((jwk) => {
                                    console.log(jwk);
                                })
                        })
                })
        })
}
