#!/usr/bin/env python

"""
JSON Web Signature

This module provides functions for signing and verifying JWS objects.

We use an in-memory representation for JOSE objects that is equivalent to
the JSON form, that is, a dictionary that can be serialized to the JOSE
JSON serialization simply by invoking json.dumps().  We will refer to these
as "unserialized JOSE objects".

Major functions provided in this module:
    - JWS sign/verify 
    - Multi-signature JWS sign/verify
"""


import json
from copy import copy
import josecrypto
from util import *
from validate import *
import serialize

supported_alg = [
    "HS256", "HS384", "HS512", 
    "RS256", "RS384", "RS512", 
    "ES256", "ES384", "ES512", 
    "PS256", "PS384", "PS512", 
]
"""
A list of "alg" values for JWS supported by this implementation
"""

supported_hdr_ext = []
"""
A list of supported header extensions.  Currently empty because
we don't support any.
"""

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
    serialized using the methods in the L{jose.serialize} module.

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

    # Check that critical header is sensible, if present
    if not compliantCrit(header):
        raise Exception("'crit' parameter contains unsuitable fields")

    # Construct the JWS Signing Input
    JWSSigningInput = createSigningInput(EncodedJWSProtectedHeader, EncodedJWSPayload)

    # Look up key
    key = josecrypto.findKey(header, keys)

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

    # Deserialize if necessary
    if not isJOSE(JWS):
        raise Exception("Cannot process something that's not a JOSE object")
    elif isJOSE_serialized(JWS):
        JWS = serialize.deserialize(JWS)

    # Make sure we have a JWS
    if not isJWS_unserialized(JWS):
        raise Exception("decrypt() called with something other than a JWS")
    
    # Handle multi-signature JWSs separately
    if isJWS_unserialized_multi(JWS):
        return verify_multi(JWS, keys)


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

    # Check that we support everything critical
    if not criticalParamsSupported(header, supported_hdr_ext):
        raise Exception("Unsupported critical fields")

    # Construct the JWS Signing Input
    JWSSigningInput = createSigningInput(EncodedJWSProtectedHeader, EncodedJWSPayload)

    # Look up the key
    key = josecrypto.findKey(header, keys)

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

    
    if not isJOSE(JWS):
        raise Exception("Cannot process something that's not a JOSE object")
    elif isJOSE_serialized(JWS):
        JWS = serialize.deserialize(JWS)

    if not isJWS_unserialized_multi(JWS):
        raise Exception("decrypt_multi called on a non-multi-signature JWS")


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

