#!/usr/bin/env python

from struct import pack, unpack
from Crypto import Random
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.Cipher import AES
from Crypto.Cipher.AES import AESCipher
from Crypto.Util.strxor import strxor
from PBKDF2 import PBKDF2
from util import b64enc, b64dec
from math import ceil

# PKCS#5 padding, since it's not in PyCrypto
def pkcs5pad(x):
    n = 16 - len(x) % 16
    if n == 0:
        n = 16
    ns = pack('B', n)
    return x + (ns * n)

def pkcs5trim(x):
    n = unpack('B', x[-1:])[0]
    return x[:-n]

# AES-CBC-HMAC compound algorithms
def AES_CBC_HMAC_encrypt(K, iv, aad, pt):
    # Select the digest to use based on key length
    seclen = dgst = None
    if len(K) == 32:
        seclen = 16
        dgst = SHA256
    elif len(K) == 48:
        seclen = 24
        dgst = SHA384
    elif len(K) == 64:
        seclen = 32
        dgst = SHA512
    else:
        raise Exception("Invalid CBC+HMAC key length: {} bytes".format(len(K)))
    # Split the key
    Ka = K[:seclen]
    Ke = K[seclen:]
    # Encrypt
    cipher = AES.new(Ke, AES.MODE_CBC, iv)
    ct = cipher.encrypt(pkcs5pad(pt))
    # MAC A || IV || E || AL
    AL = pack("!Q", 8*len(aad))
    macInput = aad + iv + ct + AL
    h = HMAC.new(Ka, digestmod=SHA256)
    h.update(macInput)
    tag = h.digest()[:seclen]
    return (ct, tag)

def AES_CBC_HMAC_decrypt(K, iv, aad, ct, tag):
    # Select the digest to use based on key length
    seclen = dgst = None
    if len(K) == 32:
        seclen = 16
        dgst = SHA256
    elif len(K) == 48:
        seclen = 24
        dgst = SHA384
    elif len(K) == 64:
        seclen = 32
        dgst = SHA512
    else:
        raise Exception("Invalid CBC+HMAC key length: {} bytes".format(len(K)))
    # Split the key
    Ka = K[:seclen]
    Ke = K[seclen:]
    # Verify A || IV || E || AL
    AL = pack("!Q", 8*len(aad))
    macInput = aad + iv + ct + AL
    h = HMAC.new(Ka, digestmod=SHA256)
    h.update(macInput)
    candidate = h.digest()[:seclen]
    verified = (candidate == tag)
    # Decrypt if verified
    if (candidate == tag):
        cipher = AES.new(Ke, AES.MODE_CBC, iv)
        pt = pkcs5trim(cipher.decrypt(ct))
        return (pt, True)
    else:
        return (None, False)

def aes_key_wrap(key, p):
    assert( len(p) % 8 == 0 )
    
    n = len(p)/8
    r = range(n+1)
    r[0] = b'\0\0\0\0\0\0\0\0'
    for i in range(1,n+1):
        r[i] = p[(i-1)*8:i*8]
    a = b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'

    aes = AESCipher(key)
    for j in range(0,6):
        for i in range(1,n+1):
            t = pack("!q", (n*j)+i)
            b = aes.encrypt(a+r[i])     # B = AES(K, A | R[i])
            a = strxor(b[:8], t)        # A = MSB(64, B) ^ t where t = (n*j)+i
            r[i] = b[8:]                # R[i] = LSB(64, B)

    r[0] = a
    return "".join(r)

def aes_key_unwrap(key, c):
    assert( len(c) % 8 == 0 )
    
    n = len(c)/8 - 1
    r = range(n+1)
    r[0] = b'\0\0\0\0\0\0\0\0'
    for i in range(1,n+1):
        r[i] = c[i*8:(i+1)*8]
    a = c[:8]

    aes = AESCipher(key)
    for j in range(5,-1,-1):
        for i in range(n,0,-1):
            t = pack("!q", (n*j)+i)
            a = strxor(a, t)
            b = aes.decrypt(a+r[i])     # B = AES-1(K, (A ^ t) | R[i]) where t = n*j+i
            a = b[:8]                   # A = MSB(64, B)
            r[i] = b[8:]                # R[i] = LSB(64, B)

    if (a == b'\xA6\xA6\xA6\xA6\xA6\xA6\xA6\xA6'):
        return "".join(r[1:])
    else:
        raise "Key unwrap integrity check failed"

def PBKDF_key_wrap(key, CEK, hashmod, dkLen, header={}):
    salt = iterCount = None
    # Pull or generate salt
    if "p2s" in header:
        salt = b64dec(header["p2s"])
    else:
        salt = Random.get_random_bytes(32)

    # Pull or generate iterCount
    if "p2c" in header:
        iterCount = b64dec(header["p2c"])
    else:
        iterCount = 2048

    # Compute the KEK and encrypt
    kek = PBKDF2(key, salt, iterCount, digestmodule=hashmod, \
        macmodule=HMAC).read(dkLen)
    encryptedKey = aes_key_wrap(kek, CEK)
    params = { "p2s": b64enc(salt), "p2c": iterCount }

    return (encryptedKey, params)

def PBKDF_key_unwrap(key, encryptedKey, hashmod, dkLen, header={}):
    # Pull salt and iterCount
    if "p2s" not in header:
        raise Exception("PBKDF2 requires 'p2s' parameter")    
    if "p2c" not in header:
        raise Exception("PBKDF2 requires 'p2c' parameter")    
    salt = b64dec(header["p2s"])
    iterCount = header["p2c"]
    
    # Compute the KEK and encrypt
    kek = PBKDF2(key, salt, iterCount, digestmodule=hashmod, \
        macmodule=HMAC).read(dkLen)
    return aes_key_unwrap(kek, encryptedKey)

def concat_SHA256(Z, dkLen, otherInfo):
    dkm = b''
    dkBytes = int(ceil(dkLen / 8.0))
    counter = 0
    while len(dkm) < dkBytes:
        counter += 1
        counterBytes = pack("!I", counter)
        dkm += SHA256.new( counterBytes + Z + otherInfo ).digest()
    return dkm[:dkBytes]

def ECDH_deriveKey(curve, key, epk, apu, apv, alg, dkLen):
    # Compute shared secret 
    Z = curve.dhZ(key, epk)
    # Derive the key
    # AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
    otherInfo = bytes(alg) + \
        pack("!I", len(apu)) + apu + \
        pack("!I", len(apv)) + apv + \
        pack("!I", dkLen)
    return concat_SHA256(Z, dkLen, otherInfo)

