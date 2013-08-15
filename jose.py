#!/usr/bin/env python

import json
import re
from copy import copy
import josecrypto
from util import b64enc, b64dec


SupportedJWSAlg = [
    # JWS
    "HS256", "HS384", "HS512", 
    "RS256", "RS384", "RS512", 
    "ES256", "ES384", "ES512", 
    "PS256", "PS384", "PS512", 
]
SupportedJWEAlg = [
    # JWE
    "dir", 
    "RSA1_5", "RSA-OAEP", 
    "A128KW", "A192KW", "A256KW", 
    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", 
    "A128GCMKW", "A192GCMKW", "A256GCMKW", 
    "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"
    
]
SupportedEnc = [
    "A128GCM", "A192GCM", "A256GCM",
    "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
]

# Convenience routines
def splitHeader(header, protect):
    if protect == "*":
        protect = header.keys()
    protected = dict([(name, header[name]) \
        for name in header if name in protect])
    unprotected = dict([(name, header[name]) \
        for name in header if name not in protect])
    return (unprotected, protected)

def joinHeader(unprotected, protected):
    header = {}
    for x in unprotected: header[x] = unprotected[x]
    for x in protected: header[x] = protected[x]
    return header

def findKey(header, keys):
    key = None
    if "kid" not in header and  len(keys) == 1:
        key = keys[0]
    elif "kid" not in header:
        raise Exception("Key must be specified by ID (kid)")
    else:
        for k in keys:
            if "kid" in k and k["kid"] == header["kid"]:
                key = k
    if key == None:
        raise Exception("Unable to locate key")
    return key

def createSigningInput(header, payload):
    return header + "." + payload
    ### XXX: With direct signing
    # if len(json.loads(header)) == 0:
    #     return b64dec(payload)
    # else:
    #     return header +"."+ payload


##### JSON WEB SIGNATURE

def sign(header, keys, payload, protect=[]):
    # TODO validate inputs

    # Capture the payload
    JWSPayload = copy(payload)
    EncodedJWSPayload = b64enc(JWSPayload)

    # Split the header
    (JWSUnprotectedHeader, JWSProtectedHeader) = splitHeader(header, protect)
    if len(JWSProtectedHeader) > 0:
        EncodedJWSProtectedHeader = b64enc(json.dumps(JWSProtectedHeader))
    else: 
        EncodedJWSProtectedHeader = ""

    # Construct the JWS Signing Input
    JWSSigningInput = createSigningInput(EncodedJWSProtectedHeader, EncodedJWSPayload)

    # Look up key
    key = findKey(header, keys)

    # Compute the signature
    JWSSignature = josecrypto.sign(header["alg"], key, JWSSigningInput)
    EncodedJWSSignature = b64enc(JWSSignature)

    # Assemble and return the object 
    JWS = {
        "payload": EncodedJWSPayload,
        "signature": EncodedJWSSignature
    }
    if len(JWSProtectedHeader) > 0:
        JWS["protected"] = EncodedJWSProtectedHeader
    if len(JWSUnprotectedHeader) > 0:
        JWS["unprotected"] = JWSUnprotectedHeader
    return JWS

def verify(JWS, keys):
    # Expand the object if it's compact
    if isJOSE_compact(JWS):
        JWS = uncompactify(JWS)
    if not isJWS(JWS):
        raise Exception("Mal-formed JWS: " + JWS)

    # Capture the payload
    EncodedJWSPayload = JWS["payload"]
    JWSPayload = b64dec(EncodedJWSPayload)

    # Reassemble the header
    JWSUnprotectedHeader = JWS["unprotected"] if ("unprotected" in JWS) else {}
    EncodedJWSProtectedHeader = JWS["protected"] if ("protected" in JWS) else ""
    if "protected" in JWS:
        EncodedJWSProtectedHeader = JWS["protected"]     
        JWSProtectedHeader = json.loads(b64dec(EncodedJWSProtectedHeader))
    else:
        EncodedJWSProtectedHeader = ""
        JWSProtectedHeader = {}
    header = joinHeader(JWSUnprotectedHeader, JWSProtectedHeader)

    # Construct the JWS Signing Input
    JWSSigningInput = createSigningInput(EncodedJWSProtectedHeader, EncodedJWSPayload)

    # Look up the key
    key = findKey(header, keys)

    # Verify the signature
    EncodedJWSSignature = JWS["signature"]
    JWSSignature = b64dec(EncodedJWSSignature)
    JWSVerificationResult = josecrypto.verify( \
        header["alg"], key, JWSSigningInput, JWSSignature )
    
    # Return the verified payload and headers 
    if JWSVerificationResult:
        return {
            "result": True,
            "payload": JWSPayload,
            "protected": JWSProtectedHeader
        }
    else: 
        return { "result": False }

def sign_multi(signers, keys, payload):
    """
    signers = [{"header", "protect"}]
    """
    # For each signer, make a JWS
    JWSs = []
    for s in signers:
        if "header" not in s:
            raise Exception("'header' required for every signer")
        protect = []
        if "protect" in s:
            protect = s["protect"]
        JWSs.append(sign(s["header"], keys, payload, protect))
    # Combine the JWSs by deleting their payloads
    JWS = { 
        "payload": b64enc(payload),
        "signatures": []
    }
    for j in JWSs:
        del j["payload"]
        JWS["signatures"].append(j)
    return JWS

def verify_multi(JWS, keys):
    if not isJWS_JSON_multi(JWS):
        raise Exception("verify_multi called on a non-multi-recipient JWS")

    # Reconstruct and validte individual JWSs for each signer
    payload = JWS["payload"]
    results = {
        "payload": b64dec(payload),
        "results": []
    }
    for s in JWS["signatures"]:
        # Make a JWS and validate it
        jws = copy(s)
        jws["payload"] = payload
        r = verify(jws, keys)

        # Add headers to the result 
        # ... so the app can tell who it's from
        if ("payload" in r):
            del  r["payload"]
        if ("unprotected" in s):
            r["unprotected"] = s["unprotected"]
        if ("protected" in s):
            r["protected"] = json.loads(b64dec(s["protected"]))
        results["results"].append(r)

    # Return the results array
    return results

##### JSON WEB ENCRYPTION

def encrypt(header, keys, plaintext, protect=[], aad=b''):
    # TODO validate input
    
    # Capture the plaintext and AAD inputs
    JWEPlaintext = copy(plaintext)
    JWEAAD = copy(aad)

    # Locate the key
    key = findKey(header, keys)
    
    # Generate cryptographic parameters according to "alg" and "enc"
    # Copy additional parameters into the header
    (CEK, JWEEncryptedKey, JWEInitializationVector, params) \
        = josecrypto.generateSenderParams(header["alg"], header["enc"], key)
    EncodedJWEInitializationVector = b64enc(JWEInitializationVector)
    EncodedJWEEncryptedKey = b64enc(JWEEncryptedKey)
    for name in params:
        header[name] = params[name]

    # Split the header
    (JWEUnprotectedHeader, JWEProtectedHeader) = splitHeader(header,protect)
    if len(JWEProtectedHeader) > 0:
        EncodedJWEProtectedHeader = b64enc(json.dumps(JWEProtectedHeader))
    else:
        EncodedJWEProtectedHeader = ""

    # Construct the AAD
    JWEAuthenticatedData = None
    if len(JWEAAD) > 0:
        JWEAuthenticatedData = EncodedJWEProtectedHeader +"."+ JWEAAD
    else:
        JWEAuthenticatedData = EncodedJWEProtectedHeader

    # Perform the encryption
    (JWECiphertext, JWEAuthenticationTag) = josecrypto.encrypt( \
        header["enc"], CEK, JWEInitializationVector, \
        JWEAuthenticatedData, JWEPlaintext )
    EncodedJWECiphertext = b64enc(JWECiphertext)
    EncodedJWEAuthenticationTag = b64enc(JWEAuthenticationTag)

    # Assemble the JWE and return
    JWE = {
        "ciphertext": EncodedJWECiphertext
    }
    if len(JWEUnprotectedHeader) > 0:
        JWE["unprotected"] = JWEUnprotectedHeader
    if len(JWEProtectedHeader) > 0:
        JWE["protected"] = EncodedJWEProtectedHeader
    if len(JWEEncryptedKey) > 0:
        JWE["encrypted_key"] = EncodedJWEEncryptedKey
    if len(JWEInitializationVector) > 0:
        JWE["iv"] = EncodedJWEInitializationVector
    if len(JWEAuthenticationTag) > 0:
        JWE["tag"] = EncodedJWEAuthenticationTag
    return JWE 

def decrypt(JWE, keys):
    # Expand the object if it's compact or serialized
    if isJOSE_compact(JWE):
        JWE = uncompactify(JWE)
    if isinstance(JWE, str):
        JWE = json.loads(JWE)
    if not isJWE(JWE):
        raise Exception("Mal-formed JWE: " + JWE)

    # Handle multi-recipient JWEs separately
    if isJWE_JSON_multi(JWE):
        return decrypt_multi(JWE, keys)

    # Capture the crypto inputs
    EncodedJWECiphertext = JWE["ciphertext"]
    EncodedJWEInitializationVector = JWE["iv"] if "iv" in JWE else ""
    EncodedJWEAuthenticationTag = JWE["tag"] if "tag" in JWE else ""
    EncodedJWEAAD = JWE["aad"] if "aad" in JWE else ""
    JWECiphertext = b64dec(EncodedJWECiphertext)
    JWEInitializationVector = b64dec(EncodedJWEInitializationVector)
    JWEAuthenticationTag = b64dec(EncodedJWEAuthenticationTag)
    JWEAAD = b64dec(EncodedJWEAAD)

    # Reassemble the header
    JWEUnprotectedHeader = JWE["unprotected"] if ("unprotected" in JWE) else {}
    if "protected" in JWE:
        EncodedJWEProtectedHeader = JWE["protected"]     
        JWEProtectedHeader = json.loads(b64dec(EncodedJWEProtectedHeader))
    else:
        EncodedJWEProtectedHeader = ""
        JWEProtectedHeader = {}
    header = joinHeader(JWEUnprotectedHeader, JWEProtectedHeader)

    # Construct the AAD
    JWEAuthenticatedData = None
    if len(JWEAAD) > 0:
        JWEAuthenticatedData = EncodedJWEProtectedHeader +"."+ JWEAAD
    else:
        JWEAuthenticatedData = EncodedJWEProtectedHeader

    # Locate the key
    key = findKey(header, keys)

    # Unwrap or derive the key according to 'alg'
    EncodedJWEEncryptedKey = JWE["encrypted_key"] if "encrypted_key" in JWE else ""
    JWEEncryptedKey = b64dec(EncodedJWEEncryptedKey)
    CEK = josecrypto.decryptKey(header["alg"], header["enc"], key, JWEEncryptedKey, header)

    # Perform the decryption
    (JWEPlaintext, JWEVerificationResult) = josecrypto.decrypt( \
        header["enc"], CEK, JWEInitializationVector, JWEAuthenticatedData, \
            JWECiphertext, JWEAuthenticationTag )
    
    # Return the results of decryption
    if JWEVerificationResult:
        return {
            "result": JWEVerificationResult,
            "plaintext": JWEPlaintext,
            "protected": JWEProtectedHeader
        }
    else:
        return { "result": JWEVerificationResult }


def encrypt_multi(header, recipients, keys, plaintext, protect=[], aad=b''):
    """
    recipients = ["header"]
    """
    # Generate random key
    if "enc" not in header:
        raise Exception("'enc' parameter must be specified in top header")
    enc = header["enc"]
    (CEK, IV) = josecrypto.generateKeyIV(enc)
    CEK_JWK = { "kty": "oct", "k": b64enc(CEK) }

    # Encrypt with "dir" (and then hide the "dir")
    if "alg" in protect:
        protect.remove(protect.index("alg"))
    header["alg"] = "dir"
    baseJWE = encrypt(header, [CEK_JWK], plaintext, protect, aad) 
    del baseJWE["unprotected"]["alg"]

    # Wrap the keys 
    wrappedKeys = []
    for r in recipients:
        # Pull and verify parameters
        if "alg" not in r:
            raise Exception("'alg' parameter required per recipient")
        alg = r["alg"]
        if alg == "dir" or alg == "ECDH-ES":
            raise Exception("Direct encryption not allowed with multi-recipient ('dir'/'ECDH-ES')")

        # Locate wrapping key and wrap key
        jwk = findKey(r, keys)
        (CEK, encryptedKey, IV, params) = josecrypto.generateSenderParams(\
            alg, enc, jwk, header=r, inCEK=CEK)
        r = joinHeader(r, params)
        wrappedKeys.append({
            "header": r,
            "encrypted_key": b64enc(encryptedKey)
        })
        
    # Assemble and return the overall JWE
    baseJWE["recipients"] = wrappedKeys
    return baseJWE

def decrypt_multi(JWE, keys):
    if not isJWE_JSON_multi(JWE):
        raise Exception("decrypt_multi called on a non-multi-recipient JWE")

    # Copy most of the JWE into a new object
    single = copy(JWE)
    del single["recipients"]

    # Find something we can use to decrypt
    selectedRecipient = None
    for r in JWE["recipients"]:
        try:
            key = findKey(r["header"], keys)
            selectedRecipient = r
        except:
            pass
    if selectedRecipient == None:
        raise Exception("Unable to locate a usable key in multi-recipient JWE")

    # Construct a standard JWE and decrypt
    if "unprotected" not in single:
        single["unprotected"] = {}
    single["unprotected"] = joinHeader(JWE["unprotected"], selectedRecipient["header"])
    single["encrypted_key"] = selectedRecipient["encrypted_key"]
    return decrypt(single, keys)


##### VALIDATION

def isJWS_JSON_single(x):
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("payload" in x and "signature" in x and \
            ("protected" in x or "unprotected" in x))

def isJWS_JSON_multi(x):
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("payload" in x and "signatures" in x)

def isJWS_JSON(x):
    return isJWS_JSON_single(x) or isJWS_JSON_multi(x)

def isJWE_JSON_single(x):
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("unprotected" in x or "protected" in x) \
       and ("ciphertext" in x)

def isJWE_JSON_multi(x):
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("ciphertext" in x and "recipients" in x) \

def isJWE_JSON(x):
    return isJWE_JSON_single(x) or isJWE_JSON_multi(x)

def isDotSeparatedBase64(x):
    return isinstance(x, basestring) \
       and re.match(r'^[a-zA-Z0-9_.-]*$', x)

def isJWS_compact(x):
    return isDotSeparatedBase64(x) \
       and len(x.split(".")) == 3

def isJWE_compact(x):
    return isDotSeparatedBase64(x) \
       and len(x.split(".")) == 5

def isJWS(x):
    return isJWS_JSON(x) or isJWS_compact(x)

def isJWE(x):
    return isJWE_JSON(x) or isJWS_compact(x)

def isJOSE_compact(x):
    return isJWS_compact(x) or isJWE_compact(x)

def isJOSE_JSON(x):
    return isJWS_JSON(x) or isJWE_JSON(x)

def isJOSE(x):
    return isJOSE_JSON(x) or isJOSE_compact(x)
    

##### COMPACTIFICATION

def compactify(jose):
    if isJWS_JSON(jose):
        if ("unprotected" in jose) or ("signatures" in jose):
            raise Exception("Non-compactable JWS")
        return ".".join([jose["protected"], jose["payload"], jose["signature"]])
    elif isJWE_JSON(jose):
        if ("unprotected" in jose) or ("recipients" in jose):
            raise Exception("Non-compactible JWE")
        if ("protected" not in jose):
            raise Exception("Empty protected header in compact object")
        protected = jose["protected"] 
        encrypted_key = jose["encrypted_key"] if "encrypted_key" in jose else ""
        iv = jose["iv"] if "iv" in jose else ""
        ciphertext = jose["ciphertext"] if "ciphertext" in jose else ""
        tag = jose["tag"] if "tag" in jose else ""
        return ".".join([protected, encrypted_key, iv, ciphertext, tag])
    else:
        raise Exception("Object must be JSON JWS or JWE")

def uncompactify(jose):
    if not isJOSE_compact(jose):
        raise Exception("Not a compact JOSE object")
    components = jose.split('.')
    if len(components) == 3:
        return {
            "protected": components[0],
            "payload": components[1],
            "signature": components[2]
        }
    elif len(components) == 5:
        return {
            "protected": components[0],
            "encrypted_key": components[1],
            "iv": components[2],
            "ciphertext": components[3],
            "tag": components[4]
        }
    else:
        raise Exception("Mal-formed compact object")
