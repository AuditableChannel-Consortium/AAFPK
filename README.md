# Accountable Assertions with Flexible Public Key

## Introduce

This project is modified from ( https://github.com/real-or-random/accas ) for hash calculation and verification of text of different public key pairs generated using private keys.

## Functionality

- Change the chameleonHash private key to $(\alpha, \omega)$ and corresponding public key to $g^{n*\omega+\alpha}$, so that the same private key can generate different public keys through $n$ .

-  $apk'\leftarrow\textsf{ChgAPK}(apk,\omega)$: The public key change algorithm takes a representative public key $apk$, and a public parameter $\omega$ as inputs, and outputs a different representative public key $apk'$, where $apk'\in [apk]_R$ for some equivalence class $[apk]_R$.
- $ask'\leftarrow\textsf{ChgASK}(ask,\omega)$: The secret key change algorithm takes a representative secret key $ask$, and a same public parameter $\omega$ as inputs, and outputs an updated secret key $ask'$.
- Validators can choose to validate individually or in batches.

## Dependencies

- [libsecp256k1](https://github.com/bitcoin/secp256k1) (full source, commit a0d3b89dd6c7b11b5a1d2d91040cc5372399b6dc, see #1)
- [Google Test](https://github.com/google/googletest/)
- [cmake](https://cmake.org/)

## Building

```shell
$ mkdir build
$ cd build
$ cmake ..
$ make
```

