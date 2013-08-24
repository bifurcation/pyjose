#!/usr/bin/env python

import jose.jwp
from jose.serialize import serialize_compact

# This should pass, with compression

header = {"alg":"none", "zip": "DEF"}
payload = "a" * 512

p1 = jose.jwp.bundle(header, payload)
c1 = serialize_compact(p1)
u1 = jose.jwp.unbundle(c1)
print c1
print u1
print


# This should fail (bad "alg")

header = {"alg": "RS256"}
payload = "payload" 

try:
    p2 = jose.jwp.bundle(header, payload)
    c2 = serialize_compact(p2)
    u2 = jose.jwp.unbundle(c2)
    print c2
    print u2
except Exception as e:
    print e
print


# This should fail (bad "crit")
header = {"alg":"none", "crit": ["ebert"]}
payload = "payload" 

try:
    p3 = jose.jwp.bundle(header, payload)
    c3 = serialize_compact(p3)
    u3 = jose.jwp.unbundle(c3)
    print c3
    print u3
except Exception as e:
    print e
print

