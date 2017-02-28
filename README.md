# pvpkcs11

[![License](https://img.shields.io/badge/license-MIT-green.svg?style=flat)](https://raw.githubusercontent.com/PeculiarVentures/2key-ratchet/master/LICENSE.md)


`pvpkcs11` consists of a input validation library (`core`) and a set of PKCS#11 implementations that wrap operating system and browser cryptographic implementations. 

We want to build a solution that provides unified access to the underlying certificate stores and associated cryptographic implementations that are available. PKCS#11 was a natural choice for an API to enable this scenario given its broad adoption, this is what motivated the creation of `pvpkcs11`.

To make the development of these platform and user agent specific PKCS#11 implementations easier and to ensure their runtime behavior is uniform we utilize a common layer we call `core `in each of the implementations to perform input validation. This is similar to how we architected `node-webcrypto-ossl`, `node-webcrypto-p11` and `webcrypto-liner` where we share `webcrypto-core`.

At this time we have only one PKCS#11 implementation, `mscapi`, but in the future we will have others as well.

![image](http://yuml.me/b60167b1)
