#!/usr/bin/env python

import jose
from jose.serialize import serialize_compact
import json

# Compression test

plaintext = "Kh" + ("a" * 512) + "n!"
jwe_header = { "alg":"A128KW", "enc":"A128GCM", "zip": "DEF" }
keys = [{ "kty":"oct", "k":"i-ueSNQgcr0q7auC8YUrYg" }]

jwe1 = jose.encrypt(jwe_header, keys, plaintext, protect="*")
dec1 = jose.decrypt(jwe1, keys)

print "Compact JWE with compression:"
#print json.dumps(jwe1, indent=4, sort_keys=True)
print serialize_compact(jwe1)
print

print "Decrypted, decompressed JWE:"
print dec1
print


# Criticality test

payload = "Some day you may pass validation.  Today is not that day."
jws_header1 = { "alg":"HS256", "crit": ["alg"] }
jws_header2 = { "alg":"HS256", "true_rings": 1, "crit": ["true_rings"] }
keys = [{ "kty":"oct", "k":"i-ueSNQgcr0q7auC8YUrYg" }]

# Test 1: Should fail on sign
try:
    jws1 = jose.sign(jws_header1, keys, payload)
    ver1 = jose.verify(jws1, keys)
except Exception as e:
    print e
print

# Test 2: Should fail on verify

try:
    jws2 = jose.sign(jws_header2, keys, payload)
    ver2 = jose.verify(jws2, keys)
except Exception as e:
    print e
print
