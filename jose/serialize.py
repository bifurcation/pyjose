#!/usr/bin/env python

"""
Serialization and deserialization of JOSE objects

This module provides functions to translate to and from the defined
JOSE serializations.  The following serializations are supported:
  - JSON
  - Compact
"""

import json
import msgpack
from copy import copy
from validate.unserialized import \
    isJOSE_unserialized, isJWS_unserialized, isJWE_unserialized, isJWP_unserialized
from util import b64enc, b64dec
                     

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
        except: 
            try: return deserialize_msgpack(x)
            except:
                raise Exception("Cannot deserialize; not a recognized serialization")

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
    
    jx = copy(jose)

    # Hunt for base64url-encoded fields and decode them
    # XXX: Hunt within unprotected headers?  Probably not
    # Top level
    binary_fields = ["protected", "payload", "signature", "encrypted_key", \
        "iv", "ciphertext", "tag"]
    for name in binary_fields:
        if name in jx:
            jx[name] = b64enc(jx[name])

    # Second level for multi-recipient/signature
    if "signatures" in jx:
        for sig in jx["signatures"]:
            if "protected" in sig: sig["protected"] = b64enc(sig["protected"])
            sig["signature"] = b64enc(sig["signature"])
    if "recipients" in jx:
        for rcpt in jx["recipients"]:
            if "encrypted_key" in rcpt: rcpt["encrypted_key"] = b64enc(rcpt["encrypted_key"])
    
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
    
    # Hunt for base64url-encoded fields and decode them
    # XXX: Hunt within unprotected headers?  Probably not
    # Top level
    binary_fields = ["protected", "payload", "signature", "encrypted_key", \
        "iv", "ciphertext", "tag"]
    for name in binary_fields:
        if name in jx:
            jx[name] = b64dec(jx[name])

    # Second level for multi-recipient/signature
    if "signatures" in jx:
        for sig in jx["signatures"]:
            if "protected" in sig: sig["protected"] = b64dec(sig["protected"])
            sig["signature"] = b64dec(sig["signature"])
    if "recipients" in jx:
        for rcpt in jx["recipients"]:
            if "encrypted_key" in rcpt: rcpt["encrypted_key"] = b64dec(rcpt["encrypted_key"])

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
    elif isJWP_unserialized(jose):
        unprotected = b64enc(json.dumps(jose["unprotected"]))
        payload = b64enc(jose["payload"])
        return ".".join([unprotected,payload])
    elif isJWS_unserialized(jose) and "unprotected" not in jose:
        return ".".join([               \
            b64enc(jose["protected"]),  \
            b64enc(jose["payload"]),    \
            b64enc(jose["signature"]) ])
    elif isJWE_unserialized(jose) and "unprotected" not in jose:
        protected = b64enc(jose["protected"])
        encrypted_key = b64enc(jose["encrypted_key"]) if "encrypted_key" in jose else ""
        iv = b64enc(jose["iv"]) if "iv" in jose else ""
        ciphertext = b64enc(jose["ciphertext"]) if "ciphertext" in jose else ""
        tag = b64enc(jose["tag"]) if "tag" in jose else ""
        return ".".join([protected, encrypted_key, iv, ciphertext, tag])
    else:
        raise Exception("Can't represent this JOSE object in the compact serialization")


def deserialize_compact(x):
    """
    Deserialize a JOSE object from the compact serialization

    @type  x: string
    @param x: A compact-format JOSE object
    @rtype: dict
    @return: The unserialized form of the input
    """
    components = x.split(".")
    if len(components) == 2:
        jose = {
            "unprotected": json.loads(b64dec(components[0])),
            "payload": b64dec(components[1])
        }
    elif len(components) == 3:
        jose = {
            "protected": b64dec(components[0]),
            "payload": b64dec(components[1]),
            "signature": b64dec(components[2])
        }
    elif len(components) == 5:
        jose = {
            "protected": b64dec(components[0]),
            "ciphertext": b64dec(components[3]),
        }
        if len(components[1]) > 0: jose["encrypted_key"] = b64dec(components[1])
        if len(components[2]) > 0: jose["iv"] = b64dec(components[2])
        if len(components[4]) > 0: jose["tag"] = b64dec(components[4])
    else:
        raise Exception("Mal-formed compact object")

    if not isJOSE_unserialized(jose):
        raise Exception("Deserialized JOSE-compact is not a JOSE object")
    return jose


def serialize_msgpack(jose):
    """
    Serialize an unserialized JOSE object to the msgpack serialization.

    @type  jose: dict
    @param jose: An unserialized JOSE object
    @rtype: bytes
    @return: The msgpack serialization of the input
    """
    if not isJOSE_unserialized(jose):
        raise Exception("Can't serialize something that's not unserialized JOSE")
    return msgpack.packb(jose)


def deserialize_msgpack(x):
    """
    Deserialize a JOSE object from the msgpack serialization

    @type  x: bytes
    @param x: A msgpack-format JOSE object
    @rtype: bytes
    @return: The unserialized form of the input
    """
    jose = msgpack.unpackb(x)
    if not isJOSE_unserialized(jose):
        raise Exception("Deserialized JOSE-msgpack is not a JOSE object")
    return jose
