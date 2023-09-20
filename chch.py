#### I. IBE using ChCh signatures.
"""
Cha-Cheon ID Based Signatures

This implementation of ID based signatures comes from J. Ayo Akinyele
  https://jhuisi.github.io/charm/charm/schemes/pksig/pksig_chch.html

ChaCheon signatures are a simple form of ID-based Signatures (IBS), based on the Boneh-Franklin IBE (Identity Based Encryption).

The original motivating scenario for IBE and IBS is somewhat unsatisfying. Actually it's more meaningful to understand these in terms of HD Wallet key derivation in cryptocurrency wallets. And actually IBS fills in the missing corner in terms of functionality.

"""

# Our setting is a symmetric bilinear group
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.pksig.pksig_chch import CHCH

group = PairingGroup('SS512')    

chch = CHCH(group)
(master_public_key, master_secret_key) = chch.setup()
ID = "janedoe@email.com"
(public_key, secret_key) = chch.keygen(master_secret_key, ID)
msg = "this is a message!"
print('msg:', msg)
signature = chch.sign(public_key, secret_key, msg)
print('signature:', signature)
chch.verify(master_public_key, public_key, msg, signature)
print('OK')
