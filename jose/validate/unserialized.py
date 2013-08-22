#!/usr/bin/env python

"""
Recognition and classification of unserialized JOSE Objects

This module provides a suite of functions that recognize various
forms of unserialized JOSE objects.
"""

import json
from .. import util

### Unserialized

def isJWS_unserialized_single(x):
    """ 
    Test whether input is a single-signature unserialized JWS object 
    @rtype: boolean
    """
    if isinstance(x, dict) \
       and "payload" in x and "signature" in x \
       and ("protected" in x or "unprotected" in x):
        try: 
            if "protected" in x: 
                json.loads(util.b64dec(x["protected"]))
            return True
        except:
            return False

def isJWS_unserialized_multi(x):
    """
    Test whether input is a multi-signature unserialized JWS object
    @rtype: boolean
    """
    return isinstance(x, dict) \
       and ("payload" in x and "signatures" in x)

def isJWS_unserialized(x):
    """
    Test whether input is an unserialized JWS object
    @rtype: boolean
    """
    return isJWS_unserialized_single(x) or isJWS_unserialized_multi(x)

def isJWE_unserialized_single(x):
    """
    Test whether input is a single-recipient unserialized JWE object
    @rtype: boolean
    """
    if isinstance(x, dict) \
       and ("unprotected" in x or "protected" in x) \
       and ("ciphertext" in x):
        #try:
        if "protected" in x:
            json.loads(util.b64dec(x["protected"]))
        return True
        #except:
        #    return False

def isJWE_unserialized_multi(x):
    """
    Test whether input is a multi-recipient unserialized JWE object
    @rtype: boolean
    """
    return ("ciphertext" in x and "recipients" in x) 

def isJWE_unserialized(x):
    """
    Test whether input is an unserialized JWE object
    @rtype: boolean
    """
    return isJWE_unserialized_single(x) or isJWE_unserialized_multi(x)

def isJOSE_unserialized(x):
    """
    Test whether input is an unserialized JOSE object
    @rtype: boolean
    """
    return isJWS_unserialized(x) or isJWE_unserialized(x)


