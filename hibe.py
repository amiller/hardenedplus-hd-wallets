import charm

"""
Hierarchical ID Based Digital signatures from BBG05
===

[1] HIBE (BBG05) from Boneh Boyen Goh 2005 
"""

## Our setting is a symmetric bilinear group
from charm.toolbox.pairinggroup import PairingGroup,ZR,G1,G2,GT,pair
from charm.schemes.pksig.pksig_chch import CHCH
group = PairingGroup('SS512')    

H1 = lambda x: group.hash(x, G1)
H2 = lambda x,y: group.hash((x,y), ZR)

g = H1('chch:g0')
g2 = H1('chch:g2')
g3 = H1('chch:g3')
DEPTH = 4
hgens = []
for i in range(DEPTH):
    hgens.append(H1(f'chch:g{i:05d}'))

class HIBE():
    def __init__(self):
        pass
    
    def setup(self, seed=None):
        a = group.random(ZR, seed=seed)
        msk = g2 ** a
        mpk = g1 = g ** a
        return (mpk, msk)

    def keygen(self, msk, ID, seed=None):
        k = len(ID)
        assert k <= DEPTH
        r = group.random(ZR, seed=seed) # TODO pseudorandom from ID
        a0 = g3
        for hi,ii in zip(hgens[:k], ID):
            a0 *= hi ** ii
        a0 **= r
        a0 *= msk
        a1 = g ** r
        bs = [h ** r for h in hgens[k:]]
        return (a0,a1) + tuple(bs)

    def encrypt(self, mpk, ID, msg, seed=None):
        k = len(ID)
        assert k <= DEPTH        
        g1 = mpk
        s = group.random(ZR, seed=seed) # TODO pseudorandom from ID        
        a = pair(g1,g2) ** s
        a *= msg
        b = g ** s
        c = g3
        for hi,ii in zip(hgens[:k],ID):
            c *= hi ** ii
        c **= s
        return a,b,c

    def decrypt(self, priv, ID, CT):
        k = len(ID)
        A, B, C = CT
        a0, a1 = priv[:2]
        bs = priv[2:]
        assert len(bs) == DEPTH-k
        M = A * pair(a1,C) / pair(B,a0)
        return M

    def derive_child(self, priv, ID, seed=None):
        k = len(ID)
        assert k <= DEPTH
        a0, a1 = priv[:2]
        bs = priv[2:]
        assert len(bs) == DEPTH-k+1
        t = group.random(ZR, seed=seed)
        A0 = g3
        for hi,ii in zip(hgens[:k],ID):
            A0 *= hi ** ii
        A0 **= t
        A0 *= a0 * (bs[0] ** ID[-1])
        A1 = a1 * g ** t 
        Bs = [bi * (hi ** t) for hi,bi in zip(hgens[k:], bs[1:])]
        return (A0,A1) + tuple(Bs)

hibe = HIBE()
(xpub, xpriv) = hibe.setup(seed=0xcafeee)
# print('xpub:',xpub)
# print('xpriv:',xpriv)

# Keygen the normal way
priv = hibe.keygen(xpriv, [0x44,0x0,0x1,0x2])
print('Keygen: OK')
# print(priv)

msg = pair(g, group.hash('chch:msg:hello', G1))
# print('msg:', msg)
ct = hibe.encrypt(xpub, [0x44,0x0,0x1,0x2], msg)
# print(ct)
print('Encrypt: OK')

msg2 = hibe.decrypt(priv, [0x44,0x0,0x1,0x2], ct)
assert(msg2 == msg)
print('Decryption and Original Message match: OK')

##### II. HIBE and Prefix delegation

# Keygen the hierarchical way
priv0 = (xpriv,1,1,1,1,1)
priv1 = hibe.derive_child(priv0, [0x44])
priv2 = hibe.derive_child(priv1, [0x44,0x0])
priv3 = hibe.derive_child(priv2, [0x44,0x0,0x1])
priv4 = hibe.derive_child(priv3, [0x44,0x0,0x1,0x2])

msg3 = hibe.decrypt(priv4, [0x44,0x0,0x1,0x2], ct)
assert(msg3 == msg)
print('Hierarchical Decryption and Original Message match: OK')
