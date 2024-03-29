from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from hibe import HIBE, group, ZR, g

"""
Hierarchical ID Based Digital signatures from BBG05
===

[1] Dirjvers Neven.
[2] BBG05 HIBE.
[3] https://eprint.iacr.org/2003/083.pdf

This is the same approach from Drijvers and Neven [1], and is basically the BBG [2] key derivation, with a generic approach for giving signatures from HIBE due to CHK07 [3]
 from 

The basic idea is the following: For a signing key of path depth D, we create a BBG key with depth D+1. The extra layer is used for the hash of the message being signed. 
 For example m/44*/0*/0*/{H(m)}

The signature is simply the BBG leaf decryption key derived from that message hash.
To verify the signature, we can just check that the decryption works successfully.

The key derivation format is analogous to BIP32
https://trezor.io/learn/a/what-is-bip32
"""

DEPTH=3

class HIBD():
    def __init__(self, ):
        self.hibe = HIBE()

    def setup(self, seed=None):
        # Setup is exactly the same as BBG05
        (mpk, msk) = self.hibe.setup(seed)
        return (mpk, msk)

    def keygen(self, msk, ID, seed=None):
        # Keygen is just the derivation up to our depth
        assert len(ID) == DEPTH
        return self.hibe.keygen(msk, ID, seed)
            
    def sign(self, priv, ID, m, seed=None):
        # Hash the message, use this to derive the last path element
        c = group.hash(m, ZR)
        # The signature is just the key
        sig = self.hibe.derive_child(priv, tuple(ID)+(c,), seed)
        return sig
    
    def verify(self, mpk, ID, m, sig, seed=None):
        # To verify the signature, need to check decryption
        mm = group.hash(m, ZR)
        M = pair(g,g)**0
        CT = self.hibe.encrypt(mpk, tuple(ID)+(mm,), M, seed=seed)
        M2 = self.hibe.decrypt(sig, tuple(ID)+(mm,), CT)
        assert M2 == M



hibd = HIBD()
(xpub, xpriv) = hibd.setup(seed=0xcafeee)
print('xpub:',xpub)
print('xpriv:',xpriv)

# Keygen for signing
priv = hibd.keygen(xpriv, [0x44,0x0,0x0])
print('Keygen: OK')
# print(priv)

# Signature
msg = 'hello wlrod'
sig = hibd.sign(priv, [0x44,0,0], msg)
# print(sig)
print('Sign: OK')

# Verify
hibd.verify(xpub, [0x44,0,0], msg, sig)
try:
    hibd.verify(xpub, [0x44,0,0], msg[:-1], sig)
except AssertionError:
    print('X Check OK')
else:
    assert False, 'failed?'
    
