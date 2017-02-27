# pvpkcs11
We want to provide an API that provides unified access to the underlying certificate stores and associated cryptographic implementations. PKCS#11 wasa natural choice for such an interface given its broad adoption, this is what motivated the creation of `pvpkcs11`.

To make the development of these varying PKCS#11 implementations easier and their runtime behavior uniform, we utilize a common layer we call `core ` for input validation. This is similar to how we architected `node-webcrypto-ossl`, `node-webcrypto-p11` and `webcrypto-liner` where we share `webcrypto-core`.

At this time we have only one PKCS#11 implementation, `mscapi`, but in the future we will have many others.

![image](https://cloud.githubusercontent.com/assets/1619279/23384355/63c91e98-fcff-11e6-95fa-f709186edbc6.png)
