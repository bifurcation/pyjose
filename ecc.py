#!/usr/bin/env python

from Crypto.Util.number import long_to_bytes, bytes_to_long
from elliptic import inv, mulp, sign_bit, y_from_x, muladdp
from curves import get_curve
from random import getrandbits
from math import ceil

# Make the EC interface more OO
class NISTEllipticCurve:
    def __init__(self, bits):
        # (bits, prime, order, p, q, point)
        (self.bits, self.p, self.N, self.a, self.b, self.G) = get_curve(bits)

    @staticmethod
    def byName(name):
        if name == "P-256":
            return NISTEllipticCurve(256)
        if name == "P-384":
            return NISTEllipticCurve(384)
        if name == "P-521":
            return NISTEllipticCurve(521)
        else:
            raise Exception("Unknown curve {}".format(name))
    
    # Get the name of this curve
    # XXX This only works because we only support prime curves right now
    def name(self):
        return "P-{}".format(self.bits)

    # Integer-to-byte-string conversion
    def int2bytes(self, x):
        return long_to_bytes(x, self.bits >> 3)
    def bytes2int(self, x):
        return bytes_to_long(x)

    # Point compression
    def compress(self, p):
        return (p[0], sign_bit(p))

    def uncompress(self, p):
        return (p[0], y_from_x(p[0], self.a, self.b, self.p, p[1]))

    # Return a new key pair for this curve
    def keyPair(self):
        priv = (getrandbits(self.bits) % (self.N - 1)) + 1
        pub = mulp(self.a, self.b, self.p, self.G, priv)
        return (priv, pub)

    def publicKeyFor(self, priv):
        return mulp(self.a, self.b, self.p, self.G, priv )

    # Compute the DH shared secret (X coordinate) from a public key and private key
    def dhZ(self, priv, pub):
        return self.int2bytes( mulp(self.a, self.b, self.p, pub, priv )[0] )
       
    # ECDSA (adapted from ecdsa.py)
    def dsaSign(self, h, priv, k=None): 
        while h > self.N:
            h >>= 1
        r = s = 0
        while r == 0 or s == 0:
            if k == None:
                k = (getrandbits(self.bits) % (self.N - 1)) + 1
            kinv = inv(k, self.N)
            kg = mulp(self.a, self.b, self.p, self.G, k)
            r = kg[0] % self.N
            if r == 0:
                continue
            s = (kinv * (h + r * priv)) % self.N
        return self.int2bytes(r) + self.int2bytes(s) 

    def dsaVerify(self, h, sig, pub):
        while h > self.N:
            h >>= 1
        intlen = int(ceil(self.bits / 8))
        r = self.bytes2int(sig[:intlen])
        s = self.bytes2int(sig[intlen:])         
        if 0 < r < self.N and 0 < s < self.N:
            w = inv(s, self.N)
            u1 = (h * w) % self.N
            u2 = (r * w) % self.N
            x, y = muladdp(self.a, self.b, self.p, self.G, u1, pub, u2)
            return r % self.N == x % self.N
        return False

P256 = NISTEllipticCurve(256)
P384 = NISTEllipticCurve(384)
P521 = NISTEllipticCurve(521)


if __name__ == "__main__":
    # Try ECDH, see if we get the same answer
    (privA, pubA) = P256.keyPair()
    (privB, pubB) = P256.keyPair()
    
    Zab = P256.dhZ( privA, pubB )
    Zba = P256.dhZ( privB, pubA )
    
    if (Zab == Zba):
        print "Passed DH test"
    
    
    # Try ECDSA with one of the NIST test vectors
    import hashlib
    msg = "5ff1fa17c2a67ce599a34688f6fb2d4a8af17532d15fa1868a598a8e6a0daf9b11edcc483d11ae003ed645c0aaccfb1e51cf448b737376d531a6dcf0429005f5e7be626b218011c6218ff32d00f30480b024ec9a3370d1d30a9c70c9f1ce6c61c9abe508d6bc4d3f2a167756613af1778f3a94e7771d5989fe856fa4df8f8ae5".decode("hex")
    h = int(hashlib.new("SHA1", msg).hexdigest(), 16)
    d =  int("002a10b1b5b9fa0b78d38ed29cd9cec18520e0fe93023e3550bb7163ab4905c6", 16)
    k = int("00c2815763d7fcb2480b39d154abc03f616f0404e11272d624e825432687092a", 16)
    Qx = int("e9cd2e8f15bd90cb0707e05ed3b601aace7ef57142a64661ea1dd7199ebba9ac", 16)
    Qy = int("c96b0115bed1c134b68f89584b040a194bfad94a404fdb37adad107d5a0b4c5e", 16)
    Q = (Qx, Qy)
    R = int("15bf46937c7a1e2fa7adc65c89fe03ae602dd7dfa6722cdafa92d624b32b156e", 16)
    S = int("59c591792ee94f0b202e7a590e70d01dd8a9774884e2b5ba9945437cfed01686", 16)
    
    sig = P256.int2bytes(R) + P256.int2bytes(S)
    ver = P256.dsaVerify(h, sig, Q)
    if ver:
        print "Passed ECDSA verification test"
    
    sig = P256.dsaSign(h, d) # NB: This will differ because of k; fix k to test generation
    ver2 = P256.dsaVerify(h, sig, Q)
    if ver2:
        print "Passed ECDSA signature test"
