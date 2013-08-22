#!/usr/bin/env python

"""
Serialization and deserialization of JOSE objects

This module provides functions to translate to and from the defined
JOSE serializations.  The following serializations are supported:
  - JSON
  - Compact
"""

import json
from validate.unserialized import \
    isJOSE_unserialized, isJWS_unserialized, isJWE_unserialized
                     

def deserialize(x):
    """
    Automatically recognize which serialization x is in, and 
    deserialize it appropriately.

    NB: To avoid circularity with the test deserializations in isJOSE_*,
    we use the fail-over model here.

    @type  x: string
    @param x: A serialized JOSE object
    @rtype: dict
    @return: An unserialized JOSE object
    """
    try: return deserialize_JSON(x)
    except:
        try: return deserialize_compact(x)
        except: raise Exception("Cannot deserialize; not a recognized serialization")

def serialize_JSON(jose):
    """
    Serialize an unserialized JOSE object to the JSON serialization

    @type  jose: dict
    @param jose: An unserialized JOSE object
    @rtype: string
    @return: The JSON serialization of the input
    """
    if not isJOSE_unserialized(jose):
        raise Exception("Can't serialize something that's not JOSE")
    return json.dumps(jose)

def deserialize_JSON(x):
    """
    Deerialize a JOSE object from the JSON serialization

    @type  x: string
    @param x: A JSON-format JOSE object
    @rtype: dict
    @return: The unserialized form of the input
    """
    try: jx = json.loads(x)
    except: raise Exception("JSON-formatted object failed JSON parsing")
    if not isJOSE_unserialized(jx):
        raise Exception("Deserialized JOSE-JSON is not a JOSE object")
    return jx

def serialize_compact(jose):
    """
    Serialize an unserialized JOSE object to the compact serialization.
    For an object to be representable in the compact serialization, it must have:
      - Only one signature / recipient
      - All header parameters protected

    If either of those conditions is false, then this function will raise
    an exception.

    @type  jose: dict
    @param jose: An unserialized JOSE object
    @rtype: string
    @return: The compact serialization of the input
    """
    if not isJOSE_unserialized(jose):
        raise Exception("Can't serialize something that's not unserialized JOSE")
    elif isJWS_unserialized(jose) and "unprotected" not in jose:
        return ".".join([jose["protected"], jose["payload"], jose["signature"]])
    elif isJWE_unserialized(jose) and "unprotected" not in jose:
        protected = jose["protected"] 
        encrypted_key = jose["encrypted_key"] if "encrypted_key" in jose else ""
        iv = jose["iv"] if "iv" in jose else ""
        ciphertext = jose["ciphertext"] if "ciphertext" in jose else ""
        tag = jose["tag"] if "tag" in jose else ""
        return ".".join([protected, encrypted_key, iv, ciphertext, tag])
    else:
        raise Exception("Can't represent this JOSE object in the compact serialization")


def deserialize_compact(x):
    """
    Deerialize a JOSE object from the compact serialization

    @type  x: string
    @param x: A compact-format JOSE object
    @rtype: dict
    @return: The unserialized form of the input
    """
    components = x.split(".")
    if len(components) == 3:
        jose = {
            "protected": components[0],
            "payload": components[1],
            "signature": components[2]
        }
    elif len(components) == 5:
        jose = {
            "protected": components[0],
            "ciphertext": components[3],
        }
        if len(components[1]) > 0: jose["encrypted_key"] = components[1]
        if len(components[2]) > 0: jose["iv"] = components[2]
        if len(components[4]) > 0: jose["tag"] = components[4]
    else:
        raise Exception("Mal-formed compact object")

    if not isJOSE_unserialized(jose):
        raise Exception("Deserialized JOSE-compact is not a JOSE object")
    return jose
