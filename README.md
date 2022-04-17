# Accountable Assertions

## Introduce

This project is modified from ( https://github.com/real-or-random/accas ) for hash calculation and verification of text of different public key pairs generated using private keys.

## Functionality

- Change the chameleonHash private key to $(\alpha, w)$ and corresponding public key to $g^{n*w+\alpha}$, so that the same private key can generate different public keys through $n$ .

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

