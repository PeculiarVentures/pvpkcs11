# pvpkcs11

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/2key-ratchet/master/LICENSE.md)

`pvpkcs11` consists of an input validation library we call `core` and a set of PKCS#11 implementations that wrap operating system and browser cryptographic and certificate store implementations. 

We wanted a solution that provides unified access to the underlying certificate stores and associated cryptographic implementations. PKCS#11 was a natural choice for an API to enable this scenario given its broad adoption.

To make the development on these platforms and user agents easier and to ensure their runtime behavior is uniform, we utilize  `core` to perform input validation. This is similar to how we architected `node-webcrypto-ossl`, `node-webcrypto-p11` and `webcrypto-liner` where we share `webcrypto-core`.

![image](https://cloud.githubusercontent.com/assets/1619279/26436272/2cea6648-40ca-11e7-904b-70432419b8dc.png)

## Approach
- Each implementation will be compiled into one library, pvpkcs11.dll/.so, and each one will be exposed via its own slot.
- RSA keys, ECDSA keys, X509 certificates, and PKCS10's can be persisted.
- Certificate store operations will be exposed as CKO_X509 
- Certificate requests will be stored via CKO_DATA.
- Both CKO_X509 and CKO_DATA will be manageable via C_CreateObject, C_DestroyObject, C_CloneObject. 
- AES keys will only be supported as session objects.

## Capabilities
- Basic certificate store management enabling access of certificates, and certificate requests as well as installation and removal.
- Basic cryptographic operations where supported by underlying cryptographic and certificate store implementation (typically RSA PKCS1, RSA-PSS, ECDSA, ECDH, and AES).
- Where ECC is supported only secp256r1, secp384r1 and secp521r1 are supported.
- Where RSA is supported only RSA 1024, 2048, 3072 and 4096 are supported.
- Where AES is supported key lengths of 128, 256,384 are supported.

## Class Design
![image](https://cloud.githubusercontent.com/assets/1619279/26436231/e7a32066-40c9-11e7-8628-bc6ac9366138.png)

## WARNING

**At this time this solution should be considered suitable for research and experimentation, further code and security review is needed before utilization in a production application.**


## Using

### Building
- At this time only MSCAPI support is implemented. 
- At this time only Windows is supported.
- The package does not have a build script at this time. 

To build you need Visual Studio and you follow the following steps:

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

### Enviroment Variables

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
- [node-webcrypto-p11](https://github.com/PeculiarVentures/node-webcrypto-p11)
- [Attacking and Fixing PKCS#11 Security Tokens](http://www.lsv.ens-cachan.fr/Publis/PAPERS/PDF/BCFS-ccs10.pdf)
