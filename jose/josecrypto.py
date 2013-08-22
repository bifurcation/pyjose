#!/usr/bin/env python

"""
High-level crypto routines for JOSE

This module exposes high-level crypto functions, at roughly the
same level of abstraction as JWE/JWS.  Specific crypto primitives
are selected using JOSE identifiers.
"""


from Crypto import Random
from Crypto.Hash import HMAC, SHA256, SHA384, SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_sig
from Crypto.Signature import PKCS1_PSS
from Crypto.Cipher import PKCS1_v1_5, PKCS1_OAEP, AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.number import long_to_bytes, bytes_to_long

import polyfills
from cryptlib.aes_gcm import AES_GCM, InvalidTagException
from cryptlib.ecc import NISTEllipticCurve, P256, P384, P521
from util import b64enc, b64dec, getOrRaise

def keyLength(enc):
    """
    Given a JOSE "enc" value, return the length in bits of the 
    key used for that encryption algorithm.

    @type enc: string
    @rtype: int
    """
    if enc in ["A128GCM"]:
        return 128
    if enc in ["A192GCM"]:
        return 192
    if enc in ["A256GCM", "A128CBC-HS256"]:
        return 256
    if enc in ["A192CBC-HS384"]:
        return 384 
    if enc in ["A256CBC-HS512"]:
        return 512
    else:
        raise Exception("Unknown key length for algorithm {}".format(enc))

def importKey(jwk, private=False):
    """
    Translate a JWK to one of the internal representations used by 
    our cryptographic libraries.
      - A symmetric key is a raw python byte string
      - An RSA public or private key is a PyCrypto RSA objects
      - An EC private key is a long
      - An EC public key is a tuple (long, long)

    @type  jwk: dict
    @param jwk: An unserialized JWK object
    @type  private: boolean
    @param private: Whether the imported key should be a private key (public default)
    @rtype: any
    @return: A native key object
    """
    kty = getOrRaise(jwk, "kty")
    if kty == "oct":
        return b64dec(getOrRaise(jwk, "k"))
    elif kty == "RSA":
        n = bytes_to_long(b64dec(getOrRaise(jwk, "n")))
        e = bytes_to_long(b64dec(getOrRaise(jwk, "e")))
        if not private:
            return RSA.construct((n,e))
        else:
            d = bytes_to_long(b64dec(getOrRaise(jwk, "d")))
            return RSA.construct((n,e,d))
    elif kty == "EC":
        if not private:
            x = bytes_to_long(b64dec(getOrRaise(jwk, "x")))
            y = bytes_to_long(b64dec(getOrRaise(jwk, "y")))
            return (x, y)
        else:
            return bytes_to_long(b64dec(getOrRaise(jwk, "d")))
    else: 
        raise Exception("Unknown key type {}".format(jwk["kty"])) 

def exportKey(key, kty, curve=None):
    """
    Translate a native key to a JWK.  The formats used for native keys
    are described in the L{importKey} method.

    The "kty" argument specifies the type of key being exported, using the
    standard JWK identifiers.  Support key types are:
      - "oct" for symmetric keys
      - "RSA" for RSA keys
      - "EC" for EC keys

    For EC keys, an elliptic curve must be specified, since this information
    is not carried in the native EC public or private key formats.

    @type  key: any
    @param key: A native key object
    @type  kty: string
    @param kty: The type of key being exported
    @type  curve: NISTEllipticCurve
    @param curve: The elliptic curve to which the given EC key belongs
    @rtype: dict
    @return: An unserialized JWK
    """
    if kty == "oct":
        return {
            "kty": kty,
            "k": b64enc(key)
        }
    elif kty == "RSA":
        jwk = {
            "kty": kty,
            "n": b64enc(long_to_bytes(key.n)),
            "e": b64enc(long_to_bytes(key.e)),
        }
        if key.has_private():
            jwk["d"] = b64enc(long_to_bytes(key.d))
        return jwk
    elif kty == "EC":
        if not curve:
            raise Exception("Curve must be provided for EC export")
        priv = pub = None
        if isinstance(key, tuple):
            pub = key
        else:
            priv = key
            pub = curve.publicKeyFor(key)
        jwk = {
            "kty": kty,
            "crv": curve.name(),
            "x": b64enc(long_to_bytes(pub[0])),
            "y": b64enc(long_to_bytes(pub[1]))
        }
        if priv:
            jwk["d"] = b64enc(long_to_bytes(priv))
        return jwk
    else: 
        raise Exception("Unknown key type {}".format(jwk["kty"])) 


def sign(alg, jwk, signingInput):
    """
    Sign an octet string with the specified algorithm and key.

    @type  alg: string
    @param alg: The JWS 'alg' value specifying the signing algorithm
    @type  jwk: dict
    @param jwk: The signing (private) key
    @type  signingInput: bytes
    @param signingInput: The octet string to be signed
    @rtype: bytes
    @return: The signature value
    """
    key = importKey(jwk, private=True)
    if alg == "HS256":
        h = HMAC.new(key, digestmod=SHA256)
        h.update(signingInput)
        return h.digest()
    elif alg == "HS384":
        h = HMAC.new(key, digestmod=SHA384)
        h.update(signingInput)
        return h.digest()
    elif alg == "HS512":
        h = HMAC.new(key, digestmod=SHA512)
        h.update(signingInput)
        return h.digest()
    elif alg == "RS256":
        h = SHA256.new(signingInput)
        signer = PKCS1_v1_5_sig.new(key)
        return signer.sign(h)
    elif alg == "RS384":
        h = SHA384.new(signingInput)
        signer = PKCS1_v1_5_sig.new(key)
        return signer.sign(h)
    elif alg == "RS512":
        h = SHA512.new(signingInput)
        signer = PKCS1_v1_5_sig.new(key)
        return signer.sign(h)
    elif alg == "ES256":
        h = bytes_to_long(SHA256.new(signingInput).digest())
        return P256.dsaSign(h, key)
    elif alg == "ES384":
        h = bytes_to_long(SHA384.new(signingInput).digest())
        sig = P384.dsaSign(h, key)
        return sig
    elif alg == "ES512":
        h = bytes_to_long(SHA512.new(signingInput).digest())
        return P521.dsaSign(h, key)
    elif alg == "PS256":
        h = SHA256.new(signingInput)
        signer = PKCS1_PSS.new(key)
        return signer.sign(h)
    elif alg == "PS384":
        h = SHA384.new(signingInput)
        signer = PKCS1_PSS.new(key)
        return signer.sign(h)
    elif alg == "PS512":
        h = SHA512.new(signingInput)
        signer = PKCS1_PSS.new(key)
        return signer.sign(h)
    elif alg == "none":
        raise Exception("DO NOT USE 'alg':'none'! NOT SECURE!")
    else:
        raise Exception("Unsupported algorithm {}".format(alg))

def verify(alg, jwk, signingInput, sig):
    """
    Verify a signature over an octet string with the specified algorithm and key.

    @type  alg: string
    @param alg: The JWS 'alg' value specifying the signing algorithm
    @type  jwk: dict
    @param jwk: The verification (public) key
    @type  signingInput: bytes
    @param signingInput: The octet string to be verified
    @type  sig: bytes
    @param sig: The signature value
    @rtype: boolean
    @return: Whether the signature verified successfully
    """

    key = importKey(jwk, private=False)
    if alg == "HS256":
        h = HMAC.new(key, digestmod=SHA256)
        h.update(signingInput)
        candidate = h.digest()
        return (candidate == sig)
    elif alg == "HS384":
        h = HMAC.new(key, digestmod=SHA384)
        h.update(signingInput)
        candidate = h.digest()
        return (candidate == sig)
    elif alg == "HS512":
        h = HMAC.new(key, digestmod=SHA512)
        h.update(signingInput)
        candidate = h.digest()
        return (candidate == sig)
    elif alg == "RS256":
        h = SHA256.new(signingInput)
        verifier = PKCS1_v1_5_sig.new(key)
        return verifier.verify(h, sig)
    elif alg == "RS384":
        h = SHA384.new(signingInput)
        verifier = PKCS1_v1_5_sig.new(key)
        return verifier.verify(h, sig)
    elif alg == "RS512":
        h = SHA512.new(signingInput)
        verifier = PKCS1_v1_5_sig.new(key)
        return verifier.verify(h, sig)
    elif alg == "ES256":
        h = bytes_to_long(SHA256.new(signingInput).digest())
        return P256.dsaVerify(h, sig, key)
    elif alg == "ES384":
        h = bytes_to_long(SHA384.new(signingInput).digest())
        return P384.dsaVerify(h, sig, key)
    elif alg == "ES512":
        h = bytes_to_long(SHA512.new(signingInput).digest())
        return P521.dsaVerify(h, sig, key)
    elif alg == "PS256":
        h = SHA256.new(signingInput)
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(h, sig)
    elif alg == "PS384":
        h = SHA384.new(signingInput)
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(h, sig)
    elif alg == "PS512":
        h = SHA512.new(signingInput)
        verifier = PKCS1_PSS.new(key)
        return verifier.verify(h, sig)
    elif alg == "none":
        raise Exception("DO NOT USE 'alg':'none'! NOT SECURE!")
    else:
        raise Exception("Unsupported signing algorithm {}".format(alg))


def generateKeyIV(enc):
    """
    Generate a key and initialization vector for the specified
    encryption algorithm.  

    @type  enc: string
    @param enc: The JWE "enc" value specifying the encryption algorithm
    @rtype: tuple
    @return: (key, iv), with both as bytes
    """
    if enc == "A128GCM":
        key = Random.get_random_bytes(16)
        iv = Random.get_random_bytes(12)
        return (key, iv)
    if enc == "A192GCM":
        key = Random.get_random_bytes(24)
        iv = Random.get_random_bytes(12)
        return (key, iv)
    if enc == "A256GCM":
        key = Random.get_random_bytes(32)
        iv = Random.get_random_bytes(12)
        return (key, iv)
    elif enc == "A128CBC-HS256":
        key = Random.get_random_bytes(32)
        iv = Random.get_random_bytes(16)
        return (key, iv)
    elif enc == "A192CBC-HS384":
        key = Random.get_random_bytes(48)
        iv = Random.get_random_bytes(16)
        return (key, iv)
    elif enc == "A256CBC-HS512":
        key = Random.get_random_bytes(64)
        iv = Random.get_random_bytes(16)
        return (key, iv)
    else: 
        raise Exception("Unsupported encryption algorithm {}".format(enc))


def generateSenderParams(alg, enc, jwk, header={}, inCEK=None):
    """
    Generate parameters for the sender of a JWE.  This is essentially an 
    encryptKey method, except (1) in some cases, the key is specified directly
    or derived ("dir", "ECDH"), and (2) other parameters besides the encrypted
    key are generated (e.g., the IV).

    This method returns several things:
      - A random CEK (can be overridden with the inCEK parameter)
      - The encrypted CEK
      - A random IV
      - A dictionary of parameters generated within this function

    The idea is that the parameters generated within this function (e.g.,
    "epk", "p2s") should be added back to the JWE header

    @type  alg: string
    @param alg: The JWE "alg" value specifying the key management algorithm
    @type  enc: string
    @param enc: The JWE "enc" value specifying the encryption algorithm
    @type  jwk: dict
    @param jwk: The key to be used, as an unserialized JWK object
    @type  header: dict
    @param header: A header object with additional parameters
    @type  inCEK: bytes
    @param inCEK: A fixed CEK (overrides random CEK generation)
    @rtype: tuple
    @return: (CEK, encryptedKey, IV, params), the first three as bytes, 
      params as dict.  
    """
    # Generate a random key/iv for enc
    (CEK, IV) = generateKeyIV(enc)
    if inCEK:
        CEK = inCEK
    encryptedKey = ""
    params = {}
    key = importKey(jwk, private=False)

    # Encrypt key / generate params as defined by alg
    if alg == "RSA1_5":
        cipher = PKCS1_v1_5.new(key)
        encryptedKey = cipher.encrypt(CEK)
    elif alg == "RSA-OAEP":
        (CEK, IV) = generateKeyIV(enc)
        cipher = PKCS1_OAEP.new(key)
        encryptedKey = cipher.encrypt(CEK)
    elif alg in ["A128KW", "A192KW", "A256KW"]:
        encryptedKey = polyfills.aes_key_wrap(key, CEK)
    elif alg == "dir":
        CEK = key
    elif alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
        # Generate the input parameters 
        apu = b64dec(header["apu"]) if "apu" in header else Random.get_random_bytes(16) 
        apv = b64dec(header["apv"]) if "apv" in header else Random.get_random_bytes(16) 
        # Generate an ephemeral key pair
        curve = NISTEllipticCurve.byName(getOrRaise(jwk, "crv"))
        if "epk" in header:
            epk = importKey(header["epk"], private=False)
            eprivk = importKey(header["epk"], private=True)
        else:
            (eprivk, epk) = curve.keyPair()
        # Derive the KEK and encrypt
        params = {
            "apu": b64enc(apu),
            "apv": b64enc(apv),
            "epk": exportKey(epk, "EC", curve)
        }
        if alg == "ECDH-ES":
            dkLen = keyLength(enc)
            CEK = polyfills.ECDH_deriveKey(curve, eprivk, key, apu, apv, enc, dkLen)
        elif alg == "ECDH-ES+A128KW":
            kek = polyfills.ECDH_deriveKey(curve, eprivk, key, apu, apv, "A128KW", 128)
            encryptedKey = polyfills.aes_key_wrap(kek, CEK)
        elif alg == "ECDH-ES+A192KW":
            kek = polyfills.ECDH_deriveKey(curve, eprivk, key, apu, apv, "A192KW", 192)
            encryptedKey = polyfills.aes_key_wrap(kek, CEK)
        elif alg == "ECDH-ES+A256KW":
            kek = polyfills.ECDH_deriveKey(curve, eprivk, key, apu, apv, "A256KW", 256)
            encryptedKey = polyfills.aes_key_wrap(kek, CEK)
    elif alg in ["A128GCMKW", "A192GCMKW", "A256GCMKW"]:
        iv = Random.get_random_bytes(12)
        gcm = AES_GCM(bytes_to_long(key))
        encryptedKey, tag = gcm.encrypt(bytes_to_long(iv), CEK, '')
        params = { "iv": b64enc(iv), "tag": b64enc(long_to_bytes(tag,16)) }
    elif alg == "PBES2-HS256+A128KW":
        (CEK, IV) = generateKeyIV(enc)
        (encryptedKey, params) = \
            polyfills.PBKDF_key_wrap( key, CEK, SHA256, 16, header )
    elif alg == "PBES2-HS384+A192KW":
        (CEK, IV) = generateKeyIV(enc)
        (encryptedKey, params) = \
            polyfills.PBKDF_key_wrap( key, CEK, SHA384, 24, header )
    elif alg == "PBES2-HS512+A256KW":
        (CEK, IV) = generateKeyIV(enc)
        (encryptedKey, params) = \
            polyfills.PBKDF_key_wrap( key, CEK, SHA512, 32, header )
    else: 
        raise Exception("Unsupported key management algorithm " + alg)
    
    return (CEK, encryptedKey, IV, params)

def decryptKey(alg, enc, jwk, encryptedKey, header={}):
    """
    Decrypt a JWE encrypted key.
    
    @type  alg: string
    @param alg: The JWE "alg" value specifying the key management algorithm
    @type  enc: string
    @param enc: The JWE "enc" value specifying the encryption algorithm
    @type  jwk: dict
    @param jwk: The key to be used, as an unserialized JWK object
    @type  encryptedKey: bytes
    @param encryptedKey: The key to decrypt
    @type  header: dict
    @param header: A header object containing additional parameters
    @rtype: bytes
    @return: The decrypted key
    """
    key = importKey(jwk, private=True)
    if alg == "RSA1_5":
        sentinel = "fnord"
        cipher = PKCS1_v1_5.new(key)
        CEK = cipher.decrypt(encryptedKey, sentinel)
        if CEK == sentinel:
            raise Exception("Unable to unwrap key")
        return CEK
    elif alg == "RSA-OAEP":
        cipher = PKCS1_OAEP.new(key)
        CEK = cipher.decrypt(encryptedKey)
        return CEK
    elif alg in ["A128KW", "A192KW", "A256KW"]:
        return polyfills.aes_key_unwrap(key, encryptedKey)
    elif alg == "dir":
        if encryptedKey and len(encryptedKey) > 0:
            raise Exception("Direct encryption with non-empty encrypted key")
        return key
    elif alg in ["ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW"]:
        # Pull the input parameters 
        epk = importKey(getOrRaise(header, "epk"))
        apu = b64dec(getOrRaise(header, "apu"))
        apv = b64dec(getOrRaise(header, "apv"))
        # Select the curve
        curve = NISTEllipticCurve.byName(getOrRaise(header["epk"], "crv"))
        # Derive the KEK and decrypt
        if alg == "ECDH-ES":
            dkLen = keyLength(enc)
            return polyfills.ECDH_deriveKey(curve, key, epk, apu, apv, enc, dkLen)
        elif alg == "ECDH-ES+A128KW":
            kek = polyfills.ECDH_deriveKey(curve, key, epk, apu, apv, "A128KW", 128)
            return polyfills.aes_key_unwrap(kek, encryptedKey)
        elif alg == "ECDH-ES+A192KW":
            kek = polyfills.ECDH_deriveKey(curve, key, epk, apu, apv, "A192KW", 192)
            return polyfills.aes_key_unwrap(kek, encryptedKey)
        elif alg == "ECDH-ES+A256KW":
            kek = polyfills.ECDH_deriveKey(curve, key, epk, apu, apv, "A256KW", 256)
            return polyfills.aes_key_unwrap(kek, encryptedKey)
    elif alg in ["A128GCMKW", "A192GCMKW", "A256GCMKW"]:
        iv = b64dec(getOrRaise(header, "iv"))
        tag = b64dec(getOrRaise(header, "tag"))
        gcm = AES_GCM(bytes_to_long(key))
        return gcm.decrypt(bytes_to_long(iv), encryptedKey, bytes_to_long(tag), '')
    elif alg == "PBES2-HS256+A128KW":
        return polyfills.PBKDF_key_unwrap(key, encryptedKey, SHA256, 16, header)
    elif alg == "PBES2-HS384+A192KW":
        return polyfills.PBKDF_key_unwrap(key, encryptedKey, SHA384, 24, header)
    elif alg == "PBES2-HS512+A256KW":
        return polyfills.PBKDF_key_unwrap(key, encryptedKey, SHA512, 32, header)
    else: 
        raise Exception("Unsupported key management algorithm " + alg)


def encrypt(enc, key, iv, aad, pt):
    """
    Encrypt JWE content.

    @type  enc: string
    @param enc: The JWE "enc" value specifying the encryption algorithm
    @type  key: bytes
    @param key: Key (CEK)
    @type  iv : bytes
    @param iv : Initialization vector
    @type  aad: bytes
    @param aad: Additional authenticated data
    @type  pt : bytes
    @param pt : Plaintext
    @rtype: tuple
    @return: (ciphertext, tag), both as bytes
    """
    if enc in ["A128GCM", "A192GCM", "A256GCM"]:
        gcm = AES_GCM(bytes_to_long(key))
        (ct, tag) = gcm.encrypt(bytes_to_long(iv), pt, aad)
        return (ct, long_to_bytes(tag, 16))
    elif enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
        return polyfills.AES_CBC_HMAC_encrypt( key, iv, aad, pt )
    else: 
        raise Exception("Unsupported encryption algorithm {}".format(enc))


def decrypt(enc, key, iv, aad, ct, tag):
    """
    Decrypt JWE content.

    @type  enc: string
    @param enc: The JWE "enc" value specifying the encryption algorithm
    @type  key: bytes
    @param key: Key (CEK)
    @type  iv : bytes
    @param iv : Initialization vector
    @type  aad: bytes
    @param aad: Additional authenticated data
    @type  ct : bytes
    @param ct : Ciphertext
    @type  tag: bytes
    @param tag: Authentication tag
    @rtype: tuple
    @return: (ciphertext, tag), both as bytes
    """
    if enc in ["A128GCM", "A192GCM", "A256GCM"]:
        gcm = AES_GCM(bytes_to_long(key))
        try:
            pt = gcm.decrypt(bytes_to_long(iv), ct, bytes_to_long(tag), aad)
            return (pt, True)
        except InvalidTagException:
            return (None, False)
    elif enc in ["A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"]:
        return polyfills.AES_CBC_HMAC_decrypt( key, iv, aad, ct, tag )
    else: 
        raise Exception("Unsupported encryption algorithm {}".format(enc))
