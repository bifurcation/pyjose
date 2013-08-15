#!/usr/bin/env python

import re
from base64 import urlsafe_b64encode, urlsafe_b64decode

# Special Base64url routines to deal with having no padding
def b64enc(x):
    return re.sub(r'=', '', urlsafe_b64encode(x))
def b64dec(x):
    if len(x) == 0:
        return b''
    return urlsafe_b64decode(str(x + '='*(4-(len(x)%4))))
