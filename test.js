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

const RSA_PKCS = {
    name: "RSASSA-PKCS1-v1_5",
    hash: "SHA-256",
    publicExponent: new Uint8Array([1, 0, 1]),
    modulusLength: 2048,
};
// const ECDSA = {
//     name: "ECDSA",
//     namedCurve: "P-384",
//     hash: "SHA-256",
// };
// const alg = {
//     name: "AES-CBC",
//     length: 256
// };

const alg = RSA_PKCS;

const data = new Buffer([1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0, 1, 2, 3, 4, 5, 6]);
const derRequest = new Buffer("3082028E30820178020100300F310D300B06035504030C045465737430820122300D06092A864886F70D01010105000382010F003082010A0282010100A4688D92031C65E8031F86E9B676A21D6BEF5441F7DD033FF166B75A0E2C87CF8697CB8B0D6374503C859E7460DB56BD3990AA6182D56A5597402D4A31052DB75D6844F01117AAF63DD2F5C121337F6F1DF82C88768E94CEE01BFF340842D5A4887AEE5E2C2DA68A2D84B3C2A9088E7AE9DCB0101A4739CED9F6F4671B685A3CC1BA186CE1416D624839E3A64B3C62A76A6E5EFD41DEBE8FDE68E2A8CBF7BB3882DDE898B9E379C074EB3A6DF7D13ECD7D8C54D78AFF201CDECFFFE78CBC14635610FE13873E796DB64D07540844CA02CF8F28D559CA920196B713C0617A61849885E114B3C36BBBC6E215B8DD91CC493CAE02F3A7B14510B9AB1B81A364547F0203010001A03C303A06092A864886F70D01090E312D302B30290603551D0E0422042064CFDCBC6CC94DC21F83B677DC013F7BA1ABB124DFA6EBF6D61169534104F22C300B06092A864886F70D01010B0382010100303CCC17B423B93570CB9E0C1022737B2A45089E099124EC388ED1DED6801133D4C957C8284E166BD0E5D8271FB4BD4F438C22050A9874F20CCF991CAB74AD1FAD74395A649DD765E2556CE068A6CB2FC57272F359F6A0CBB3136464EF84C8008C6DE521D34B5EB2639E9B805C8DF39ACEBCA455D6DE1A2C56E2A14344DD8CE5CDC0C18A5D699A533E441DE8F0F5BD12DA4E98293EC56221D2A79C4019C5FF1A1BCCC6FC95F60407A02D5ED8A201332C4394F0524CDAF20C5559FBF581E005B3292490C2C100B3CAC7A8CF3619830ED3E4E0CDD35C7A60CFB6A706BB4F9E2E35E150D26D4BDE1DD78696701B3B7C8F8193C6B29A54F454DE861DF9688DED2F14", "hex");

function hex2b64url(hex) {
    return helper.Convert.ToBase64Url(helper.Convert.FromHex(hex));
}

let promise = Promise.resolve()


// Iterations
const iterations = 1

for (var i = 0; i < iterations; i++) {
    let iter = i;
    promise = promise
        .then(() => {
            let msg = `Iteration #${iter}`;

            // return p11.certStorage.importCert("request", derRequest, alg, ["verify"])
            //     .then((item) => {
            //         console.log(item);
            //     })
            return p11.certStorage.keys()
                .then((indexes) => {
                    console.log(indexes);

                    let promise = Promise.resolve()

                    // return p11.certStorage.removeItem(indexes[2]);
                })
                .then(() => {
                    return p11.keyStorage.keys()
                })
                .then((indexes) => {
                    console.log(indexes);
                    return p11.keyStorage.clear();
                })
        })

}

promise
    .then(() => {
        console.log("Success");
    })
    // @ts-ignore
    .catch((err) => {
        console.error(err);
    });


