# pvpkcs11

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/2key-ratchet/master/LICENSE.md)


`pvpkcs11` consists of a input validation library we call `core` and a set of PKCS#11 implementations that wrap operating system and browser cryptographic and certificate store implementations. 

We wanted a solution that provides unified access to the underlying certificate stores and associated cryptographic implementations in a uniform way. PKCS#11 was a natural choice for an API to enable this scenario given its broad adoption.

To make the development on these platforms and user agents easier and to ensure their runtime behavior is uniform, we utilize  `core` to perform input validation. This is similar to how we architected `node-webcrypto-ossl`, `node-webcrypto-p11` and `webcrypto-liner` where we share `webcrypto-core`.

At this time we have only one PKCS#11 implementation, `mscapi`, but in the future we will have others as well.

![image](http://yuml.me/b60167b1)

## Approach
- Each implementation will be compiled into one library, pvpkcs11.dll/.so that will be exposed via it's own slot.
- Certificate store operations will be exposed via CKO_X509 only C_CreateObject, C_DestroyObject, C_CloneObject will be supported.
- Certificate requests will be stored via CKO_DATA and if the underlying store supports storage of requests that will be used.
- AES keys will only be supported as session objects.
- RSA keys, ECDSA keys, X509 certificates, and PKCS10's can be persisted.


## Capabilities
- Basic certificate store management enabling access of certificates, and certificate requests as well as installation and removal.
- Basic cryptographic operations where supported by underying cryptographic and certificate store implementation (typically RSA PKCS1, RSA PSS, ECDSA, ECDH, and AES).
- Where ECC is supported only secp256r1, secp384r1 and secp521r1 are supported.
- Where RSA is supported RSA 1024, 2048, 3072 and 4096 are supported.


## WARNING

**At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.**


## Using

### Building
At this time only MSCAPI.dll is implemented, it also does not have a build script at this time. To build you need Visual Studio and you follow the following steps:

- build.bat
- open build/binding.snl
- Run build

### Testing

- Install dependencies

```
npm install
```

- Run tests

```
npm test
```

### System variables

| Name              | Value | Description                                                              |
|-------------------|-------|--------------------------------------------------------------------------|
| `PV_PKCS11_ERROR` | true  | Prints to stdout additional information about errors from PKCS#11 module |


### Supported Algorithms

#### MSCAPI

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
