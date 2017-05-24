# pvpkcs11

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/2key-ratchet/master/LICENSE.md)


`pvpkcs11` consists of a input validation library (`core`) and a set of PKCS#11 implementations that wrap operating system and browser cryptographic implementations. 

We want to build a solution that provides unified access to the underlying certificate stores and associated cryptographic implementations that are available. PKCS#11 was a natural choice for an API to enable this scenario given its broad adoption, this is what motivated the creation of `pvpkcs11`.

To make the development of these platform and user agent specific PKCS#11 implementations easier and to ensure their runtime behavior is uniform we utilize a common layer we call `core `in each of the implementations to perform input validation. This is similar to how we architected `node-webcrypto-ossl`, `node-webcrypto-p11` and `webcrypto-liner` where we share `webcrypto-core`.

At this time we have only one PKCS#11 implementation, `mscapi`, but in the future we will have others as well.

![image](http://yuml.me/b60167b1)

## Capabilities
- Basic certificate store management enabling access of certificates, and certificate requests as well as installation and removal.
- Basic cryptographic operations where supported by underying cryptographic and certificate store implementation (typically RSA PKCS1, RSA PSS, ECDSA, ECDH, and AES).
- Where ECC is supported only secp256r1, secp384r1 and secp521r1 are supported.
- Where RSA is supported RSA 1024, 2048, 3072 and 4096 are supported.

## Using

### Building
At this time only MSCAPI.dll is implemented, it also does not have a build script at this time. To build you need Visual Studio and you follow the following steps:

- build.bat
- open build/binding.snl
- Run build

### System variables

| Name              | Value | Description                                                              |
|-------------------|-------|--------------------------------------------------------------------------|
| `PV_PKCS11_ERROR` | true  | Prints to stdout additional information about errors from PKCS#11 module |


### Supported Algorithms

#### MSCAPI.dll

| Function   | Algorithms                                                                          |
|------------|-------------------------------------------------------------------------------------|
| Hash       | SHA1; SHA2; SHA384; SHA512                                                          |
| Sign       | RSA /w SHA1; RSA PKCS1 /w SHA1, SHA2;  RSA PSS /w SHA1, SHA2;  ECDSA /w SHA1, SHA2  |
| Exchange   | ~~ECDH /w SHA1~~                                                                    |
| Encryption | RSA OAEP; AES modes CBC, CBC-PAD, GCM, and ECB                                      |

## Related
- [webcrypto-local](https://github.com/PeculiarVentures/webcrypto-local)
- [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
- [Attacking and Fixing PKCS#11 Security Tokens](http://www.lsv.ens-cachan.fr/Publis/PAPERS/PDF/BCFS-ccs10.pdf)
