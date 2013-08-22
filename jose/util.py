#!/usr/bin/env python

"""
Utility functions for JOSE

This module provides a set of convenience functions for JOSE processing.
  - Base64 encoding and decoding without padding
  - Header splitting and joining
  - Key lookup
  - "crit" header checking
  - Generation of input to signing / authentication
"""

import re
from base64 import urlsafe_b64encode, urlsafe_b64decode

#############################
# Base64

def b64enc(buf):
    """
    URL-safe Base64 encode, without padding characters

    @type  buf: Sequence type (string, bytearray, etc.)
    @param buf: An octet string to be encoded
    @rtype: string
    @return: The base64url encoding of the input, without padding
    """
    return re.sub(r'=', '', urlsafe_b64encode(buf))


def b64dec(s):
    """
    URL-safe Base64 decode, adding padding characters as necessary

    @type  s: string
    @param s: A base64url-encoded string (padding optional)
    @rtype: byte string
    @return: The octet string decoded from the encoded value
    """
    if len(s) == 0:
        return b''
    return urlsafe_b64decode(str(s + '='*(4-(len(s)%4))))


#############################
# Dicionary accessors

def getOrRaise(obj, name):
    """
    Returns the value in the dictionary, or raises an exception 
    if the indicated name is not present.

    @type  obj: dict
    @type  name: string
    @rtype: any
    """
    if name not in obj:
        raise Exception("'{}' parameter required but not found".format(name))
    return obj[name]

def getOrEmpty(obj, name):
    """
    Returns the value in the dictionary, or the empty string if
    the indicated name is not present.

    @type  obj: dict
    @type  name: string
    @rtype: any
    """
    if name not in obj:
        return ""
    else:
        return obj[name]


#############################
# Data structure manipulation 

def splitHeader(header, protect):
    """
    Splits an overall header into "unprotected" and "protected"
    parts, using a list of protected fields.  Fields in the list
    are moved to the "protected" dictionary, while fields
    not on the list are moved to the "unprotected" dictionary.

    This is the inverse of the L{joinHeader} function.

    @type  header : dict
    @param header : Overall dictionary of header parameters 
    @type  protect: list of string
    @param protect: List of fields in the header to be split out
    @rtype: (dict, dict)
    @return: A tuple of two dictionaries.  The first is the 
      unprotected header, and the second is the protected.
    """
    if protect == "*":
        protect = header.keys()
    protected = dict([(name, header[name]) \
        for name in header if name in protect])
    unprotected = dict([(name, header[name]) \
        for name in header if name not in protect])
    return (unprotected, protected)

def joinHeader(unprotected, protected):
    """
    Merges two dictionaries into one.  If the same fields 
    appear in both dictionaries, the value from the protected
    dictionary overwrites the value from the unprotected.

    This is the inverse of the L{splitHeader} function.

    @type  unprotected: dict
    @param unprotected: Dictionary of unprotected header parameters 
    @type  protected  : dict
    @param protected  : Dictionary of protected header parameters
    @rtype: dict
    @return: The merger of the two inputs
    """
    header = {}
    for x in unprotected: header[x] = unprotected[x]
    for x in protected: header[x] = protected[x]
    return header

def compliantCrit(header):
    """
    Check that the "crit" parameter, if present, is non-empty, and does 
    not contain any standard fields, duplicate fields, or fields not 
    in the header. 

    @type  header: dict
    @param header: JWS or JWE header
    @rtype: boolean
    """
    if "crit" not in header:
        return True
    
    crit = header["crit"]
    critset = set(crit)
    standard = set(["alg", "enc", "zip", "crit", "typ", "cty", \
                "kid", "jwk", "jku", "x5c", "x5u", "x5t"])
    if not isinstance(crit, list):
        return False
    elif len(crit) == 0:
        # MUST NOT be empty
        return False
    elif len(crit) != len(critset):
        # MUST NOT contain duplicate entries
        return False
    elif not critset <= set(header.keys()):
        # MUST NOT contain entries not in the header
        return False
    elif len(critset & standard) > 0:
        # MUST NOT contain standard fields
        return False
    else:
        return True

def criticalParamsSupported(header, supported):
    """
    Check whether the header contains a "crit" parameter, and if so,
    whether all critical fields are supported.

    @type  header: dict
    @param header: JWS or JWE header
    @type  supported: list
    @param supported: List of supported header extensions
    @rtype: boolean
    """
    if "crit" not in header:
        return True
    for key in header["crit"]:
        if key not in header:
            # This is weird, but not a failure
            pass
        if key not in supported:
            return False
    return True

def createSigningInput(header, payload, JWE=False):
    """
    Create the input for signing (JWS) or authentication (JWE),
    given an Encoded Protected Header and Encoded Payload.
    
    @type  header : string
    @param header : Serialized, base64url-encoded protected header
    @type  payload: string
    @param payload: Base64url-encoded payload or 'aad' value
    @rtype: string
    @return: Value to be used as JWS Signing Input or JWE 
      Additional Authenticated Data
    """
    if not JWE:
        return header + "." + payload
    else:
        if len(payload) > 0:
            return header +"."+ payload
        else:
            return header
    ### XXX: With direct signing (ISSUE-59)
    # if len(json.loads(header)) == 0:
    #     return b64dec(payload)
    # else:
    #     return header +"."+ payload

