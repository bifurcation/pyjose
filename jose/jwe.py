#!/usr/bin/env python

"""
JSON Web Encryption

This module provides functions for encrypting and decrypting JWE objects.

We use an in-memory representation for JOSE objects that is equivalent to
the JSON form, that is, a dictionary that can be serialized to the JOSE
JSON serialization simply by invoking json.dumps().  We will refer to these
as "unserialized JOSE objects".

Major functions provided in this module:
    - JWE encrypt/decrypt
    - Mutli-recipient JWE encrypt/decrypt
"""


import json
import zlib
from copy import copy
import josecrypto
from util import *
from validate import *
import serialize

supported_alg = [
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

supported_enc = [
    "A128GCM", "A192GCM", "A256GCM",
    "A128CBC-HS256", "A192CBC-HS384", "A256CBC-HS512"
]
"""
A list of "enc" value for JWE supported by this implementation
"""

supported_hdr_ext = []
"""
A list of supported header extensions.  Currently empty because
we don't support any.
"""


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
    serialized using the methods in the L{jose.serialize} module.

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

    # Compress the plaintext if required
    if "zip" in header and header["zip"] == "DEF":
        JWEPlaintext = zlib.compress(JWEPlaintext)

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

    # Deserialize if necessary
    if not isJOSE(JWE):
        raise Exception("Cannot process something that's not a JOSE object")
    elif isJOSE_serialized(JWE):
        JWE = serialize.deserialize(JWE)

    # Make sure we have a JWE
    if not isJWE_unserialized(JWE):
        raise Exception("decrypt() called with something other than a JWE")

    # Handle multi-recipient JWEs separately
    if isJWE_unserialized_multi(JWE):
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

    # Check that we support everything critical
    if not criticalParamsSupported(header, supported_hdr_ext):
        raise Exception("Unsupported critical fields")    

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
    
    # Decompress the plaintext if necessary
    if "zip" in header and header["zip"] == "DEF":
        JWEPlaintext = zlib.decompress(JWEPlaintext)

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
    if not isJOSE(JWE):
        raise Exception("Cannot process something that's not a JOSE object")
    elif isJOSE_serialized(JWE):
        JWE = serialize.deserialize(JWE)

    if not isJWE_unserialized_multi(JWE):
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
