// @ts-check

const pkcs11 = require("pkcs11js");

const mod = new pkcs11.PKCS11();

mod.load("out/Debug_x64/libpvpkcs11.dylib");

mod.C_Initialize();

console.log("Slots:", mod.C_GetSlotList().length);

const slot = mod.C_GetSlotList()[0];

const session = mod.C_OpenSession(slot, 2 | 4);

mod.C_DigestInit(session, {mechanism: pkcs11.CKM_SHA_1, parameter: null});
const digest = mod.C_Digest(session, new Buffer("hello"), new Buffer(20));

console.log(digest.toString("hex"));

mod.C_Finalize();