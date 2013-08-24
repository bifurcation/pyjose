#!/usr/bin/env python

"""
Recognition and classification of serialized JOSE Objects

This module provides a suite of functions that recognize various
forms of serialized JOSE objects.
"""

from jose.serialize import deserialize_compact, deserialize_JSON, deserialize_msgpack
from unserialized import *


### JSON-serialized

def isJWP_JSON(x):
    """
    Test whether input is a JWP-JSON object
    @rtype: boolean
    """
    try: return isJWP_unserialized(deserialize_JSON(x))
    except: return False


def isJWS_JSON_single(x):
    """ 
    Test whether input is a single-signature JWS-JSON object 
    @rtype: boolean
    """
    try: return isJWS_unserialized_single(deserialize_JSON(x)) 
    except: return False

def isJWS_JSON_multi(x):
    """
    Test whether input is a multi-signature JWS-JSON object
    @rtype: boolean
    """
    try: return isJWS_unserialized_multi(deserialize_JSON(x)) 
    except: return False

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
    try: return isJWE_unserialized_single(deserialize_JSON(x)) 
    except: return False

def isJWE_JSON_multi(x):
    """
    Test whether input is a multi-recipient JWE-JSON object
    @rtype: boolean
    """
    try: return isJWE_unserialized_multi(deserialize_JSON(x)) 
    except: return False

def isJWE_JSON(x):
    """
    Test whether input is a JWE-JSON object
    @rtype: boolean
    """
    return isJWE_JSON_single(x) or isJWE_JSON_multi(x)

def isJOSE_JSON(x):
    """
    Test whether input is a JOSE-JSON object
    @rtype: boolean
    """
    return isJWS_JSON(x) or isJWE_JSON(x) or isJWP_JSON(x)

### Compact-serialized

def isJWP_compact(x):
    """
    Test whether input is a JWP-compact object
    @rtype: boolean
    """
    try: return isJWP_unserialized(deserialize_compact(x))
    except: return False

def isJWS_compact(x):
    """
    Test whether input is a JWS-compact object
    @rtype: boolean
    """
    try: return isJWS_unserialized_single(deserialize_compact(x)) 
    except: return False

def isJWE_compact(x):
    """
    Test whether input is a JWE-compact object
    @rtype: boolean
    """
    try: return isJWE_unserialized_single(deserialize_compact(x)) 
    except: return False

def isJOSE_compact(x):
    """
    Test whether input is a JOSE-compact object
    @rtype: boolean
    """
    return isJWS_compact(x) or isJWE_compact(x) or isJWP_compact(x)


### msgpack-serialized

def isJWP_msgpack(x):
    """
    Test whether input is a JWP-msgpack object
    @rtype: boolean
    """
    try: return isJWP_unserialized(deserialize_msgpack(x))
    except: return False

def isJWS_msgpack_single(x):
    """ 
    Test whether input is a single-signature JWS-msgpack object 
    @rtype: boolean
    """
    try: return isJWS_unserialized_single(deserialize_msgpack(x)) 
    except: return False

def isJWS_msgpack_multi(x):
    """
    Test whether input is a multi-signature JWS-msgpack object
    @rtype: boolean
    """
    try: return isJWS_unserialized_multi(deserialize_msgpack(x)) 
    except: return False

def isJWS_msgpack(x):
    """
    Test whether input is a JWS-msgpack object
    @rtype: boolean
    """
    return isJWS_msgpack_single(x) or isJWS_msgpack_multi(x)

def isJWE_msgpack_single(x):
    """
    Test whether input is a single-recipient JWE-msgpack object
    @rtype: boolean
    """
    try: return isJWE_unserialized_single(deserialize_msgpack(x)) 
    except: return False

def isJWE_msgpack_multi(x):
    """
    Test whether input is a multi-recipient JWE-msgpack object
    @rtype: boolean
    """
    try: return isJWE_unserialized_multi(deserialize_msgpack(x)) 
    except: return False

def isJWE_msgpack(x):
    """
    Test whether input is a JWE-msgpack object
    @rtype: boolean
    """
    return isJWE_msgpack_single(x) or isJWE_msgpack_multi(x)

def isJOSE_msgpack(x):
    """
    Test whether input is a JOSE-msgpack object
    @rtype: boolean
    """
    return isJWS_msgpack(x) or isJWE_msgpack(x) or isJWP_msgpack(x)
