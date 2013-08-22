#!/usr/bin/env python

"""
Recognition and Classification of JOSE Objects

This module provides a suite of functions that recognize various
forms of JOSE objects.  The "serialized" and "unserialized" modules
are separated to avoid circular dependencies with the serialization
module.  This package imports all of their symbols, though so you
can just import everything you need from here::
  
  import jose.validate

  jose.validate.isJOSE(x)
  jose.validate.isJWS_unserialized(x)
  jose.validate.isJWE_compact(x)
  # etc.
"""

from unserialized import *
from serialized import *

### JOSE general

def isJOSE_serialized(x):
    """
    Test whether input is a serialized JOSE object
    @rtype: boolean
    """
    return isJOSE_JSON(x) or isJOSE_compact(x)

def isJWS(x):
    """
    Test whether input is a JWS object (compact or JSON)
    @rtype: boolean
    """
    return isJWS_unserialized(x) or isJWS_JSON(x) or isJWS_compact(x)

def isJWE(x):
    """
    Test whether input is a JWE object (compact or JSON)
    @rtype: boolean
    """
    return isJWE_unserialized(x) or isJWE_JSON(x) or isJWS_compact(x)

def isJOSE(x):
    """
    Test whether input is a JOSE object (JWE or JWS; JSON or compact)
    @rtype: boolean
    """
    return isJOSE_unserialized(x) or isJOSE_serialized(x)

