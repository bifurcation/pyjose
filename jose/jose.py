#!/usr/bin/env python

"""
Main JOSE API functions

This module provides functions for creating and processing JOSE objects.
We use an in-memory representation for JOSE objects that is equivalent to
the JSON form, that is, a dictionary that can be serialized to the JOSE
JSON serialization simply by invoking json.dumps().  We will refer to these
as "unserialized JOSE objects".

Major functions provided in this module:
    - JWS sign/verify 
    - JWE encrypt/decrypt
    - Multi-signature JWS sign/verify
    - Mutli-recipient JWE encrypt/decrypt
    - Recognition and classification of JOSE objects
    - Translation to/from the compact serialization
"""


import json
import re
from copy import copy
import josecrypto
from util import *


SupportedJWSAlg = [
    # JWS
    "HS256", "HS384", "HS512", 
    "RS256", "RS384", "RS512", 
    "ES256", "ES384", "ES512", 
    "PS256", "PS384", "PS512", 
]
"""
A list of "alg" values for JWS supported by this implementation
"""

SupportedJWEAlg = [
    # JWE
    "dir", 
    "RSA1_5", "RSA-OAEP", 
    "A128KW", "A192KW", "A256KW", 
    "ECDH-ES", "ECDH-ES+A128KW", "ECDH-ES+A192KW", "ECDH-ES+A256KW", 
    "A128GCMKW", "A192GCMKW", "A256GCMKW", 
    "PBES2-HS256+A128KW", "PBES2-HS384+A192KW", "PBES2-HS512+A256KW"
]
"""
A list of "alg" values for JWE supported by this implementation
"""


SupportedEnc = [
    "A128GCM", "A192GCM", "A256GCM",
    "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
]
"""
A list of "enc" value for JWE supported by this implementation
"""



##### JSON WEB SIGNATURE

def sign(header, keys, payload, protect=[]):
    """
    Sign a payload and construct a JWS to encode the signature.

    To perform a JWS signature, we take four inputs, one of which is optional:
      1. A header describing how the signature should be done
      2. A set of keys from which the signing key will be selected
      3. A payload to be signed
      4. (optional) A list of header fields to be integrity-protected

    The implementation then splits the header into unprotected and protected
    parts, computes the signature according to the header, and assembles the 
    final object.

    The JWS object returned is unserialized.  It has the same structure as a 
    JSON-formatted JWS object, but it is still a python dictionary.  It can be
    JSON serialized using the standard python json.dumps method, or compact
    serialized using the L{compactify} method below.

    @type  header : dict
    @param header : Dictionary of JWS header parameters
    @type  keys   : list or set of JWK
    @param keys   : Set of keys from which the signing key will be selected (
      based on the header)
    @type  payload: byte string
    @param payload: The payload to be signed
    @type  protect: list of string / string
    @param protect: List of header fields to protect, or the string "*" to
      indicate that all header fields should be protected
    @rtype: dict
    @return: Unserialized JWS object
    """

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
    """
    Verify a JWS object

    To verify a JWS object, we require two inputs: 
      1. The JWS object to be verified
      2. A set of keys from which to draw the public key or shared key

    (This implementation does not currently support using the "jwk" attribute
    for a public key, so the key must be provided.)

    This method returns verification results as a dictionary with the following
    fields:
      - "result": The boolean result of the verification
      - "protected": (optional) The protected headers, as a dictionary
      - "payload": (optional) The signed payload

    If the verification succeeds, the "result" field will be set to True, and 
    the "protected" and "payload" fields will be populated.  If verification
    fails, then the "result" field will be set to False, and the other two
    fields will not be present.

    @type  JWS : dict
    @param JWS : Unserialized JWS object 
    @type  keys: list or set of JWK
    @param keys: Set of keys from which the public/shared key will be selected (
      based on the header)
    @rtype: dict
    @return: Verification results, including the boolean result and, if succesful,
      the signed header parameters and payload
    """

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
    Generate a multi-signature JWS object 

    A multi-signature JWS object is equivalent to several individual
    JWS objects with the same payload.  Thus, the inputs to this method
    are largely similar to the L{sign} method.
      1. A list of per-signer information, with one dictionary per 
         signer, with the following keys:
           - "header": (required) Header parameters describing the signature
           - "protect": (optional) A list of headers names to be protected, 
             or the string "*" to indicate that all headers should be protected
      2. A set of keys from which signing keys will be drawn
      3. A payload to be signed
      
    Like the L{sign} function, this function returns an unserialized JWS 
    object.  The only difference is that the output of this function will
    have multiple signatures.

    @type  signers: list or set of dict
    @param signers: List of per-signer signing instructions
    @type  keys   : list or set of JWK
    @param keys   : Set of keys from which the signing key will be selected (
      based on the header)
    @type  payload: byte string
    @param payload: The payload to be signed
    @rtype: dict
    @return: Unserialized JWS object
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
    """
    Verify a multi-signer JWS object

    B{You should not have to use this method directly, since the L{verify} method
    will transparently handle multiple-signature objects.}

    To verify a JWS object, we require two inputs: 
      1. The JWS object to be verified
      2. A set of keys from which keys for verification will be drawn

    (This implementation does not currently support using the "jwk" attribute
    for a public key, so the key must be provided.)

    This method returns a dictionary describing the results of the validation,
    including the following fields
      - "payload": The payload used for verification
      - "results": The a list of results per signature, as a dictionary with
        the following fields:
          - "result": The boolean verification result
          - "unprotected": (optional) Unprotected headers for this signature
          - "protected": (optional) Protected headers for this signature

    Note that unlike the single-recipient L{verify} method, this method 
    returns the payload and headers regardless of whether any verification
    succeeded.  This allows applications to merge multiple signatures in
    several different possible ways.  Applications should be careful, however
    that they do not assume that just because a payload is present it is 
    verified.

    @type  JWS : dict
    @param JWS : Unserialized JWS object 
    @type  keys: list or set of JWK
    @param keys: Set of keys from which verification keys will be selected (
      based on the header)
    @rtype: list
    @return: Verification results, including for each signature the boolean 
      result and, if succesful, the signed header parameters and payload
    """

    
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
    """
    Encrypt a payload and construct a JWE to encode the encrypted content.

    To perform a JWE encryption, we take five inputs, two of which are optional:
      1. A header describing how the encryption should be done
      2. A set of keys from which the encryption key will be selected
      3. A plaintext to be encrypted
      4. (optional) A list of header fields to be integrity-protected
      5. (optional) An explicit Additional Authenticated Data value

    The implementation then splits the header into unprotected and protected
    parts, computes the ciphertext and tag according to the header, and assembles 
    the  final object.

    The JWE object returned is unserialized.  It has the same structure as a 
    JSON-formatted JWE object, but it is still a python dictionary.  It can be
    JSON serialized using the standard python json.dumps method, or compact
    serialized using the L{compactify} method below.

    @type  header   : dict
    @param header   : Dictionary of JWE header parameters
    @type  keys     : list or set of JWK
    @param keys     : Set of keys from which the signing key will be selected
                      (based on the header)
    @type  plaintext: byte string
    @param plaintext: The payload to be encrypted
    @type  protect  : list of string / string
    @param protect  : List of header fields to protect, or the string "*" to
    @type  aad      : byte string
    @param aad      : Payload to be authenticated, but not encrypted
                      indicate that all header fields should be protected
    @rtype: dict
    @return: Unserialized JWS object
    """
    # TODO validate input
    
    # Capture the plaintext and AAD inputs
    JWEPlaintext = copy(plaintext)
    JWEAAD = copy(aad)

    # Locate the key
    key = findKey(header, keys)
    
    # Generate cryptographic parameters according to "alg" and "enc"
    # Copy additional parameters into the header
    (CEK, JWEEncryptedKey, JWEInitializationVector, params) \
        = josecrypto.generateSenderParams( \
            header["alg"], header["enc"], key, header=header)
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
    JWEAuthenticatedData = createSigningInput( \
        EncodedJWEProtectedHeader, JWEAAD, JWE=True)

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
    """
    Decrypt and verify a JWE object

    To decrypt a JWE object, we require two inputs: 
      1. The JWE object to be decrypted
      2. A set of keys from which to draw the public key or shared key

    This function returns decryption/verification results as a 
    dictionary with the following fields:
      - "result": The boolean result of the verification
      - "protected": (optional) The protected headers, as a dictionary
      - "plaintext": (optional) The signed payload

    If the verification succeeds, the "result" field will be set to True, and 
    the "protected" and "payload" fields will be populated.  If verification
    fails, then the "plaintext" field will be set to False, and the other two
    fields will not be present.

    @type  JWE : dict
    @param JWE : Unserialized JWS object 
    @type  keys: list or set of JWK
    @param keys: Set of keys from which the decryption key will be selected
    @rtype: dict
    @return: Decryption results, including the boolean result and, if succesful,
      the signed header parameters and payload
    """


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
    JWEAuthenticatedData = createSigningInput( \
        EncodedJWEProtectedHeader, JWEAAD, JWE=True)

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

    Generate a multi-recipient JWE object 

    A multi-recipient JWS object is equivalent to several individual
    JWE objects with the same payload and the same CEK.  Thus, the 
    inputs to this method are largely similar to the L{encrypt} method.
      1. A header describing how the encryption should be done
      2. A list of per-recipient headers
      3. A set of keys from which the encryption key will be selected
      4. A plaintext to be encrypted
      5. (optional) A list of global header fields to be integrity-protected
      6. (optional) An explicit Additional Authenticated Data value
      
    Like the L{encrypt} function, this function returns an unserialized JWS 
    object.  The only difference is that the output of this function will
    have multiple recipients.

    Note that while some or all of the global header parameters may be 
    protected (according to the 'protect' argument), all per-recipient
    header parameters are unprotected.

    @type  header   : dict
    @param header   : Dictionary of JWE header parameters
    @type  recipients: list of dict
    @param recipients: List of per-recipient header dictionaries
    @type  keys     : list or set of JWK
    @param keys     : Set of keys from which the signing key will be selected
                      (based on the header)
    @type  plaintext: byte string
    @param plaintext: The payload to be encrypted
    @type  protect  : list of string / string
    @param protect  : List of header fields to protect, or the string "*" to
    @type  aad      : byte string
    @param aad      : Payload to be authenticated, but not encrypted
                      indicate that all header fields should be protected
    @rtype: dict
    @return: Unserialized JWS object
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
    """
    Decrypt and verify a multi-recipient JWE object

    B{You should not have to use this method directly, since the L{decrypt} method
    will transparently handle multiple-recipient objects.}

    To decrypt a multi-recipient JWE object, we require two inputs: 
      1. The JWE object to be decrypted
      2. A set of keys from which to draw the public key or shared key

    This method identifies whether it can use one of the per-recipient 
    structures in the JWE to decrypt the object.  If so, it performs the
    decryption and returns the results as a dictionary of the same form 
    as the L{decrypt} method.

    If the verification succeeds, the "result" field will be set to True, and 
    the "protected" and "payload" fields will be populated.  If verification
    fails, then the "plaintext" field will be set to False, and the other two
    fields will not be present.

    @type  JWE : dict
    @param JWE : Unserialized JWS object 
    @type  keys: list or set of JWK
    @param keys: Set of keys from which the decryption key will be selected
    @rtype: dict
    @return: Decryption results, including the boolean result and, if succesful,
      the signed header parameters and payload
    """

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
    """ 
    Test whether input is a single-signature JWS-JSON object 
    @rtype: boolean
    """
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("payload" in x and "signature" in x and \
            ("protected" in x or "unprotected" in x))

def isJWS_JSON_multi(x):
    """
    Test whether input is a multi-signature JWS-JSON object
    @rtype: boolean
    """
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("payload" in x and "signatures" in x)

def isJWS_JSON(x):
    """
    Test whether input is a JWS-JSON object
    @rtype: boolean
    """
    return isJWS_JSON_single(x) or isJWS_JSON_multi(x)

def isJWE_JSON_single(x):
    """
    Test whether input is a single-recipient JWE-JSON object
    @rtype: boolean
    """
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("unprotected" in x or "protected" in x) \
       and ("ciphertext" in x)

def isJWE_JSON_multi(x):
    """
    Test whether input is a multi-recipient JWE-JSON object
    @rtype: boolean
    """
    if isinstance(x, basestring):
        try: x = json.loads(x)
        except: return False
    return ("ciphertext" in x and "recipients" in x) \

def isJWE_JSON(x):
    """
    Test whether input is a JWE-JSON object
    @rtype: boolean
    """
    return isJWE_JSON_single(x) or isJWE_JSON_multi(x)

def isDotSeparatedBase64(x):
    """
    Test whether input is a set of base64url-encoded strings
    @rtype: boolean
    """
    return isinstance(x, basestring) \
       and re.match(r'^[a-zA-Z0-9_.-]*$', x)

def isJWS_compact(x):
    """
    Test whether input is a JWS-compact object
    @rtype: boolean
    """
    return isDotSeparatedBase64(x) \
       and len(x.split(".")) == 3

def isJWE_compact(x):
    """
    Test whether input is a JWE-compact object
    @rtype: boolean
    """
    return isDotSeparatedBase64(x) \
       and len(x.split(".")) == 5

def isJWS(x):
    """
    Test whether input is a JWS object (compact or JSON)
    @rtype: boolean
    """
    return isJWS_JSON(x) or isJWS_compact(x)

def isJWE(x):
    """
    Test whether input is a JWE object (compact or JSON)
    @rtype: boolean
    """
    return isJWE_JSON(x) or isJWS_compact(x)

def isJOSE_compact(x):
    """
    Test whether input is a compact JOSE object (JWE or JWS)
    @rtype: boolean
    """
    return isJWS_compact(x) or isJWE_compact(x)

def isJOSE_JSON(x):
    """
    Test whether input is a JSON JOSE object (JWE or JWS)
    @rtype: boolean
    """
    return isJWS_JSON(x) or isJWE_JSON(x)

def isJOSE(x):
    """
    Test whether input is a JOSE object (JWE or JWS; JSON or compact)
    @rtype: boolean
    """
    return isJOSE_JSON(x) or isJOSE_compact(x)
    

##### COMPACTIFICATION

def compactify(jose):
    """
    Translates a JOSE object to compact form. For an object 
    to be compactible, it must have:
      - Only one signature / recipient
      - All header parameters protected

    If either of those conditions is false, then this function will raise
    an exception.

    @type  jose: dict
    @param jose: Unserialized JOSE object
    @rtype: string
    @return: Compact-format JOSE object
    """
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
    """
    Deserialize a compact-format JOSE object into a structure
    resembling a JSON-formatted JOSE object

    @type  jose: string
    @param jose: Compact-format JOSE object
    @rtype: dict
    @return: Unserialized JOSE object
    """
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
