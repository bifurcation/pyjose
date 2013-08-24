#!/usr/bin/env python

"""
JSON Web Payload

JWP is a representation of a payload and header, but with no cryptographic 
protection.  Thus, the main value added by JWP is in:
  - Common high-level structure with JWP and JWE
  - Compression with the "zip" header
  - Criticality with the "crit" header

Since there's no cryptography going on, it's not as clear for JWP what the
relevant verbs are for creation and parsing of objects.  So we use the 
verbs "bundle" and "unbundle", respectively.
"""

import json
import zlib
from copy import copy
from util import *
from validate import *
import serialize

supported_alg = [
    "none"
]
"""
A list of "alg" values for JWP supported by this implementation
"""

supported_hdr_ext = []
"""
A list of supported header extensions.  Currently empty because
we don't support any.
"""

def bundle(header, payload):
    """
    Construct a JWP to encode the header and payload.  
    
    Also performs compression if required by "zip", and verifies that 
    the "crit" header is well-formed.

    @type  header : dict
    @param header : Dictionary of JWP header parameters
    @type  payload: byte string
    @param payload: The payload to be signed
    @rtype: dict
    @return: Unserialized JWP object
    """
    # TODO validate inputs

    # Capture the payload and header
    JWPHeader = copy(header)
    JWPPayload = copy(payload)
    
    # Verify that if "alg" is present, it is set to "none"
    if "alg" not in JWPHeader:
        JWPHeader["alg"] == "none"
    if JWPHeader["alg"] != "none":
        raise Exception("'alg' value in JWP header must be 'none'")

    # Check that critical header is sensible, if present
    if not compliantCrit(JWPHeader):
        raise Exception("'crit' parameter contains unsuitable fields")

    # Perform compression if required
    if "zip" in JWPHeader and JWPHeader["zip"] == "DEF":
        JWPPayload = zlib.compress(JWPPayload)

    # Assemble and return the object 
    JWP = {
        "unprotected": JWPHeader,
        "payload": JWPPayload
    }
    return JWP

def unbundle(JWP):
    """
    Unbundle a JWP object

    Also performs decompression if required by "zip", and verification of
    support for fields in the "crit" header.

    @type  JWP : dict
    @param JWP : Unserialized JWP object 
    @rtype: dict
    @return: Verification results, including the boolean result and, if succesful,
      the signed header parameters and payload
    """

    # Deserialize if necessary
    if not isJOSE(JWP):
        raise Exception("Cannot process something that's not a JOSE object")
    elif isJOSE_serialized(JWP):
        JWP = serialize.deserialize(JWP)

    # Make sure we have a JWP
    if not isJWP_unserialized(JWP):
        raise Exception("decrypt() called with something other than a JWP")

    # Capture the payload and header
    JWPHeader = JWP["unprotected"]
    JWPPayload = JWP["payload"]
    
    # Verify that if "alg" is present, it is set to "none"
    if "alg" not in JWPHeader or JWPHeader["alg"] != "none":
        raise Exception("'alg' value in JWP header must be 'none'")

    # Check that we support everything critical
    if not criticalParamsSupported(JWPHeader, supported_hdr_ext):
        raise Exception("Unsupported critical fields")

    # Decompress if required
    if "zip" in JWPHeader and JWPHeader["zip"] == "DEF":
        JWPPayload = zlib.decompress(JWPPayload)
    
    # Return the verified payload and headers 
    return {
        "unprotected": JWPHeader,
        "payload": JWPPayload
    }
