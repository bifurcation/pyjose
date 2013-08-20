#!/usr/bin/env python

from jose import *

keys = [
    {
        "kty": "RSA",
        "kid": "rsa",
        "n":"ofgWCuLjybRlzo0tZWJjNiuSfb4p4fAkd_wWJcyQoTbji9k0l8W26mPddxHmfHQp-Vaw-4qPCJrcS2mJPMEzP1Pt0Bm4d4QlL-yRT-SFd2lZS-pCgNMsD1W_YpRPEwOWvG6b32690r2jZ47soMZo9wGzjb_7OMg0LOL-bSf63kpaSHSXndS5z5rexMdbBYUsLA9e-KXBdQOS-UTo7WTBEMa2R2CapHg665xsmtdVMTBQY4uDZlxvb3qCo5ZwKh9kG4LT6_I5IhlJH7aGhyxXFvUK-DWNmoudF8NAco9_h9iaGNj8q2ethFkMLs91kzk2PAcDTW9gb54h4FRWyuXpoQ",
        "e":"AQAB",
        "d":"Eq5xpGnNCivDflJsRQBXHx1hdR1k6Ulwe2JZD50LpXyWPEAeP88vLNO97IjlA7_GQ5sLKMgvfTeXZx9SE-7YwVol2NXOoAJe46sui395IW_GO-pWJ1O0BkTGoVEn2bKVRUCgu-GjBVaYLU6f3l9kJfFNS3E0QbVdxzubSu3Mkqzjkn439X0M_V51gfpRLI9JYanrC4D4qAdGcopV_0ZHHzQlBjudU2QvXt4ehNYTCBr6XCLQUShb1juUO1ZdiYoFaFQT5Tw8bGUl_x_jTj3ccPDVZFD9pIuhLhBOneufuBiB4cS98l2SR_RQyGWSeWjnczT0QU91p1DhOVRuOopznQ"
    },
    {
        "kty":"EC",
        "kid":"ec256",
        "crv":"P-256",
        "x":"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU",
        "y":"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0",
        "d":"jpsQnnGQmL-YBIffH1136cspYG6-0iY7X1fCE9-E9LI"
    },
    {
        'kty': 'EC',
        'kid': 'ec384',
        'crv': 'P-384',
        'x': '-qvvx9HZZRtGndke5SnZ2gXk6csit0uagJMtz6JrN82ZXYXof7ANjBli1NFsYu1K',
        'y': '1iRqc9gfL5h4DRHKteh0ok_cfXJ8TmBO28j7djl5BzLbbpvmuekjVCqP2uX_BvT5',
        'd': 'iSE433j4C7rPY6AD3sHeGsNqHLczBnKz_Y3oieDHdamqvU6XdOqAeLJ595tIC8-H'
    }, {
        'kty': 'EC',
        'crv': 'P-521',
        'kid': 'ec521',
        'x': '0Waix0O2wmSiXv6DL5TGoQwAfTf-wEDzZXqra-zSRCZhxay5zTauAZHeSaHrPCke5B8rVzDx0mv5wNOdPGpI7lY',
        'y': 'AQ9Vj81SQKqiJSoRt6g5BmaftuNKyt70v0qf2BnAdc9TsS4JyZNLUV2b5sKZnpG9a_P4DVgVheLiMfxUiiCJK-5t',
        'd': 'plEhLthi8ZkjuTycpb6QKqX9oUk5cnW1aLRcZlaxVPS-6JHUHszaJOyQXX71kTDu5EDTAIfYC9y6G-pV3LErBmQ'
    },
    { "kty":"oct", "kid":"oct128", "k":"ptFc4_gODAFn-tiDFqjigQ" },
    { "kty":"oct", "kid":"oct192", "k":"SiEiTR9nEmIJbJ0JCiX9-6LA9NiLvaea" },
    { "kty":"oct", "kid":"oct256", "k":"fNG9W8GRU0UA4tlPQuEW32TxQC-DxIuT+Qvo67sCZSM" },
    { "kty":"oct", "kid":"oct384", "k":"PWIWXRO2PI3RD3eXNPdW2hpArZCGzBW9piKdKMsgRxJaUvqXvIEGl-XbiX6Dgq02" },
    { "kty":"oct", "kid":"oct512", "k":"8iVxdXIhvvZHBwHgmEvSnSAP2yORqLH7HMk23QUUilV-0dm1SPR9qmyLKywz6nblobmK7VTt0Ae1uf2YiWr81g" },
]

kidMap = {
    # JWS
    "HS256": "oct128",
    "HS384": "oct192",
    "HS512": "oct256", 
    "RS256": "rsa",
    "RS384": "rsa",
    "RS512": "rsa", 
    "ES256": "ec256",
    "ES384": "ec384",
    "ES512": "ec521", 
    "PS256": "rsa",
    "PS384": "rsa",
    "PS512": "rsa", 
    # JWE
    "dir": "oct128", 
    "RSA1_5": "rsa",
    "RSA-OAEP": "rsa", 
    "A128KW": "oct128",
    "A192KW": "oct192",
    "A256KW": "oct256", 
    "ECDH-ES": "ec256",
    "ECDH-ES+A128KW": "ec256",
    "ECDH-ES+A192KW": "ec384",
    "ECDH-ES+A256KW": "ec521", 
    "A128GCMKW": "oct128",
    "A192GCMKW": "oct192",
    "A256GCMKW": "oct256", 
    "PBES2-HS256+A128KW": "oct128",
    "PBES2-HS384+A192KW": "oct192", 
    "PBES2-HS512+A256KW": "oct256"
}

encMap = {
    "A128GCM": "oct128", 
    "A192GCM": "oct192", 
    "A256GCM": "oct256",
    "A128CBC-HS256": "oct256", 
    "A192CBC-HS384": "oct384", 
    "A256CBC-HS512": "oct512"
}

ProtectionLevels = [
    "*",
    ["alg"],
    []
]

fmt = "| {:3s} | {:20s} | {:15s} | {:7s} | {:7s} | {:7s} |"
div = "|:----|:---------------------|:----------------|:--------|:--------|:--------|"
testix = 0
def reportResult(testix, alg, enc, level, valid, correct):
    print fmt.format(str(testix), alg, enc, str(level), str(valid), str(correct))

testJWSbasic = True
testJWEbasic = True
testJWSmulti = True
testJWEmulti = True


# Print a header 

print div
print fmt.format("", "alg", "enc", "protect", "valid", "correct")
print div


# Test all JWS algorithms

if testJWSbasic:
    payload = "Dixitque Deus fiat lux et facta est lux"
    for alg in SupportedJWSAlg:
        for p in ProtectionLevels:
            testix += 1
            header = {
                "alg": alg,
                "kid": kidMap[alg]
            }
        
            jws = sign(header, keys, payload, p)
            result = verify(jws, keys)
            vpayload = result["payload"] if "payload" in result else ""
            correct = (payload == vpayload) 
            reportResult(testix, alg, "", p, result["result"], correct)
    print div

# Test all JWE algorithms (alg and enc)

if testJWEbasic:
    payload = "In tenebris collocavit me quasi mortuos sempiternos."
    for alg in SupportedJWEAlg:
        for enc in SupportedEnc:
            for p in ProtectionLevels:
                testix += 1
                header = {
                    "alg": alg,
                    "enc": enc,
                    "kid": kidMap[alg]
                }
                if alg == "dir":
                    header["kid"] = encMap[enc]
            
                # Test with all headers protected
                jwe = encrypt(header, keys, payload, protect="*")
                result = decrypt(jwe, keys)
                plaintext = result["plaintext"] if "plaintext" in result else ""
                correct = (payload == plaintext) 
                reportResult(testix, alg, enc, p, result["result"], correct)
    print div


# Test multi-signer


if testJWSmulti:
    testix += 1
    payload = "Quare fremuerunt gentes et populi meditati sunt inania"
    signers = [
        { "header": { "alg": "RS256", "kid": "rsa" } },
        { "header": { "alg": "ES256", "kid": "ec256" } }
    ]
    jwsm = sign_multi(signers, keys, payload)
    resm = verify_multi(jwsm, keys)

    valid = True
    for v in [ r["result"] for r in resm["results"] ]:
        valid = (valid and v)
    correct = (payload == resm["payload"])
    reportResult(testix, "multi-sign", "", "[]", valid, correct)
    print div

# Test multi-recipient

if testJWEmulti:
    payload = "Quare fremuerunt gentes et populi meditati sunt inania"
    header = { "enc": "A128CBC-HS256" }
    recipients = [
        { "alg": "A128KW", "kid": "oct128" },
        { "alg": "ECDH-ES+A128KW", "kid": "ec256" }
    ]
    jwem = encrypt_multi(header, recipients, keys, payload)
    decm0 = decrypt(jwem, keys)      # all
    decm1 = decrypt(jwem, [keys[1]]) # ec256
    decm2 = decrypt(jwem, [keys[4]]) # oct128

    valid = (decm0["result"] and decm1["result"] and decm2["result"])
    correct = (payload == decm0["plaintext"]) \
          and (payload == decm1["plaintext"]) \
          and (payload == decm2["plaintext"])
    reportResult(testix, "multi-rcpt", "", "[]", valid, correct)
    print div
