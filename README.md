# PyJOSE

This library enables JSON-based encryption and signing the latest version of the JOSE specifications:
* [JSON Web Encryption][JWE]
* [JSON Web Signature][JWS]
* [JSON Web Key][JWK]
* [JSON Web Encryption][JWA]

In general, I try to be compliant to the specs as written.  In some areas where the spec is ambiguous, I've made choices.  There may be particular divergence in the JSON serialization, but that's largely because that serialization is very ambiguous in the current spec.  

Note 1: All of the JWA algorithms are implemented here, except for "none" which *should not be used*

Note 2: This is very much a work in progress, so bugs may be plentiful, and documentation sparse.


## Really Quick Start

```
$ sudo python setup.py install
$ python -c "import jose.tests.quickstart"
$ python -c "import jose.tests.examples"
$ python -c "import jose.tests.testall"
```


## Quick Tour

```
#!/usr/bin/env python

import jose
from jose.serialize import serialize_compact

plaintext = "Attack at dawn!"
jwe_header = { "alg":"A128KW", "enc":"A128GCM" }
jws_header = { "alg":"HS256" }
keys = [{ "kty":"oct", "k":"i-ueSNQgcr0q7auC8YUrYg" }]

# Encrypt into the JSON serialization
jwe1 = jose.encrypt(jwe_header, keys, plaintext)
dec1 = jose.decrypt(jwe1, keys)

# Encrypt into the compact serialization
jwe2 = serialize_compact( \
        jose.encrypt(jwe_header, keys, plaintext, protect="*"))
dec2 = jose.decrypt(jwe2, keys)

# Sign into the JSON serialization
jws1 = jose.sign(jws_header, keys, plaintext)
ver1 = jose.verify(jws1, keys)

# Sign into the compact serialization
jws2 = serialize_compact( \
        jose.sign(jws_header, keys, plaintext, protect="*"))
ver2 = jose.verify(jws2, keys)
```


## Guide to files:
* Tests using this JOSE implementation
    * examples.py: Examples from the JOSE specs
    * testall.py: Complete test of all algorithms 
    * quickstart.py: The above example
* JOSE library
    * jose.py: Top-level JOSE functions
    * josecrypt.py: JOSE-level crypto routines, indexed by JOSE identifiers
    * util.py: JOSE-ish base64 function
* Crypto Polyfills (mine)
    * ecc.py: ECDH and ECDSA implementation, adapted from 
    * polyfills.py: Polyfills for crypto algorithms not in libraries, as well as JOSE combinations
* Crypto libraries (someone else's)
    * aes_gcm.py: AES-GCM implementation
    * elliptic.py: Elliptic curve math
    * curves.py: NIST elliptic curve constants
    * PBKDF2.py: PyCrypto implementation of PBKDF2


## Algorithm support

| Alg                | Requirement    | Status  | Source           |
|--------------------|----------------|---------|------------------|
| HS256              | REQUIRED       | DONE    | [PyCrypto][]     |
| HS384              | OPTIONAL       | DONE    | [PyCrypto][]     |
| HS512              | OPTIONAL       | DONE    | [PyCrypto][]     |
| RS256              | RECOMMENDED    | DONE    | [PyCrypto][]     |
| RS384              | OPTIONAL       | DONE    | [PyCrypto][]     |
| RS512              | OPTIONAL       | DONE    | [PyCrypto][]     |
| ES256              | RECOMMENDED+   | DONE    | [PyECC][]        |
| ES384              | OPTIONAL       | DONE    | [PyECC][]        |
| ES512              | OPTIONAL       | DONE    | [PyECC][]        |
| PS256              | OPTIONAL       | DONE    | [PyCrypto][]     |
| PS384              | OPTIONAL       | DONE    | [PyCrypto][]     |
| PS512              | OPTIONAL       | DONE    | [PyCrypto][]     |
| none               | REQUIRED       | NO WAY  |                  |
|                    |                |         |                  |
| RSA1_5             | REQUIRED       | DONE    | [PyCrypto][]     |
| RSA-OAEP           | OPTIONAL       | DONE    | [PyCrypto][]     |
| A128KW             | RECOMMENDED    | DONE    | *polyfill*       |
| A192KW             | OPTIONAL       | DONE    | *polyfill*       |
| A256KW             | RECOMMENDED    | DONE    | *polyfill*       |
| dir                | RECOMMENDED    | DONE    | [PyCrypto][]     |
| ECDH-ES            | RECOMMENDED+   |         | *polyfill*       |
| ECDH-ES+A128KW     | RECOMMENDED    |         | *polyfill*       |
| ECDH-ES+A192KW     | OPTIONAL       |         | *polyfill*       |
| ECDH-ES+A256KW     | RECOMMENDED    |         | *polyfill*       |
| A128GCMKW          | OPTIONAL       | DONE    | [AES-GCM-Python] |
| A192GCMKW          | OPTIONAL       | DONE    | [AES-GCM-Python] |
| A256GCMKW          | OPTIONAL       | DONE    | [AES-GCM-Python] |
| PBES2-HS256+A128KW | OPTIONAL       |         | *polyfill*       |
| PBES2-HS384+A192KW | OPTIONAL       |         | *polyfill*       |
| PBES2-HS512+A256KW | OPTIONAL       |         | *polyfill*       |
|                    |                |         |                  |
| A128CBC-HS256      | REQUIRED       | DONE    | *polyfill*       |
| A192CBC-HS384      | OPTIONAL       | DONE    | *polyfill*       |
| A256CBC-HS512      | REQUIRED       | DONE    | *polyfill*       |
| A128GCM            | RECOMMENDED    | DONE    | [AES-GCM-Python] |
| A192GCM            | OPTIONAL       | DONE    | [AES-GCM-Python] |
| A256GCM            | RECOMMENDED    | DONE    | [AES-GCM-Python] |

[JWE]: http://tools.ietf.org/html/draft-ietf-jose-json-web-encryption
[JWS]: http://tools.ietf.org/html/draft-ietf-jose-json-web-signature
[JWK]: http://tools.ietf.org/html/draft-ietf-jose-json-web-key
[JWA]: http://tools.ietf.org/html/draft-ietf-jose-json-web-algorithms
[PyCrypto]: https://www.dlitz.net/software/pycrypto/
[PyECC]: https://github.com/amintos/PyECC
[AES-GCM-Python]: https://github.com/bozhu/AES-GCM-Python

