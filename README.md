# Hardened-Plus key derivation using Identity Based Cryptography

Ordinary crypto wallet key derivation (like in Bitcoin and Ethereum, see [BIP32](https://trezor.io/learn/a/what-is-bip32)) presents you with a dilemma.
There are two bonus features: _hardening_, and `xpub` keys. Without hardening, a single private key and `xpub`, or two private keys, can be used to decrypt the entire master key.
With hardening, the `xpub` is useless, can't be used to derive individual keys. Why can't we have both?

With Identity Based Cryptgraphy, we can fix this.

More specifically, in hierarchical deterministic wallets, we always have a master private key `xpriv`, that can be used to derive private keys according to a path string, like `m/44/0/0/...`. The "hierarchical" bit means that you can delegate subkeys like `m/44/0` that can be used like wildcard, i.e. they can sign for keys under their subtree like `m/44/0/*/*/...`.

with normal key derivation using key derivation paths like `m/44/0/0/...`, we also have a master public key `xpub` that can be used to derive the public keys for each path. It acts like a viewing key. (See for instance this [xpub tool](https://blockpath.com/wallets/local/101?action=appxpub)).
However, the downside of normal key derivation is that the keys are not truly isolated. Either two private keys, or one private key and the `xpub`, can be used to derive the master key.

Hardened keys use a different path identifier, like `m/44'/0'/0'/...`, where hardening acts like a circuit breaker. The private keys are all now properly isolated from each other, but there is no longer an `xpub` that can be used to derive public keys.

## Hardened-Plus Derivation this with Hierarchical ID Based Digital Signatures (HIBD)

Identity Based Cryptography is a useful way to approach this problem. The proposal is to define a signature scheme supporting derivation paths such as `m/44*/0*/0*` which support both _hardening_ as well as useful `xpub` keys.

There is a general approach to key distribution that works for hierarchical encryption and digital signatures like this, based on pairings. [(BBG05)](https://eprint.iacr.org/2005/015)
This is ordinarily presented for hierarchical ID based encryption, but there is a generic transformation from HIBE encryption to signatures [(GS02)](https://eprint.iacr.org/2002/056), so we implement that here.

Because this uses pairing, it cannot be implemented using `secp256k1`, but might be a good fit for `BLS12-381` or related. This is an implementation in [Charm](https://jhuisi.github.io/charm/) using a symmetric bilinear group.

## Hierarchical IBE from BBG05

See [./hibe.py](./hibe.py) for an implementation of hierarchical identity based encryption

## Hierarchical ID Based signatures from Cha-Cheon signatures.

See [./hibd.py](./hibd.py) for an implementation of the proposed `m/44*/0*/0*/...` "hardened plus xpub"


## Setup

This uses a Docker file to build Charm.

```bash
docker build -t hibe .
```

```bash
docker run -it hibe
```