#!/usr/bin/env python

import jose

plaintext = "Attack at dawn!"
jwe_header = { "alg":"A128KW", "enc":"A128GCM" }
jws_header = { "alg":"HS256" }
keys = [{ "kty":"oct", "k":"i-ueSNQgcr0q7auC8YUrYg" }]

# Encrypt into the JSON serialization
jwe1 = jose.encrypt(jwe_header, keys, plaintext)
dec1 = jose.decrypt(jwe1, keys)
print jwe1
print dec1
print

# Encrypt into the compact serialization
jwe2 = jose.compactify( \
        jose.encrypt(jwe_header, keys, plaintext, protect="*"))
dec2 = jose.decrypt(jwe2, keys)
print jwe2
print dec2
print

# Sign into the JSON serialization
jws1 = jose.sign(jws_header, keys, plaintext)
ver1 = jose.verify(jws1, keys)
print jws1
print ver1
print

# Sign into the compact serialization
jws2 = jose.compactify( \
        jose.sign(jws_header, keys, plaintext, protect="*"))
ver2 = jose.verify(jws2, keys)
print jws2
print ver2
print

