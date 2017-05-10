/// <reference path="mocha" />
const pkcs11 = require("pkcs11js");
const assert = require("assert");

const config = require("./test/config");

let mod = new pkcs11.PKCS11();;
let slot, slots;

mod.load(config.lib);
mod.C_Initialize();
slots = mod.C_GetSlotList();
slot = slots[0];

const session = mod.C_OpenSession(slot, 4);

const privateTemplate = [
    { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
    { type: pkcs11.CKA_SIGN, value: true },
    // { type: pkcs11.CKA_DECRYPT, value: true },
    // { type: pkcs11.CKA_UNWRAP, value: true },
];
const publicTemplate = [
    { type: pkcs11.CKA_ID, value: new Buffer("1234567890") },
    { type: pkcs11.CKA_EC_POINT, value: new Buffer("06082A8648CE3D030107", "hex") },
    // { type: pkcs11.CKA_PUBLIC_EXPONENT, value: new Buffer([1, 0, 1]) },
    // { type: pkcs11.CKA_MODULUS_BITS, value: 1024 },
    { type: pkcs11.CKA_VERIFY, value: true },
    // { type: pkcs11.CKA_ENCRYPT, value: true },
    // { type: pkcs11.CKA_WRAP, value: true },
];

const parameter = null;
// const parameter = {
//     hashAlg: pkcs11.CKM_SHA_1,
//     mgf: pkcs11.CKG_MGF1_SHA1,
//     saltLen: 1,
//     type: pkcs11.CK_PARAMS_RSA_PSS
// };

const keys = mod.C_GenerateKeyPair(session, { mechanism: pkcs11.CKM_ECDSA_KEY_PAIR_GEN, parameter: null }, publicTemplate, privateTemplate);

const mechanism = { mechanism: pkcs11.CKM_ECDSA_SHA1, parameter };

mod.C_SignInit(session, mechanism, keys.privateKey);

mod.C_SignUpdate(session, new Buffer("first"));
mod.C_SignUpdate(session, new Buffer("second"));

const signature = mod.C_SignFinal(session, new Buffer(1024));

console.log(signature.toString("hex"));

mod.C_VerifyInit(session, mechanism, keys.publicKey);

mod.C_VerifyUpdate(session, new Buffer("first"));
mod.C_VerifyUpdate(session, new Buffer("second"));

const res = mod.C_VerifyFinal(session, signature);

console.log(res);

mod.C_CloseSession(session);

mod.C_Finalize();