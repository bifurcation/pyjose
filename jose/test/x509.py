import jose
from copy import copy

jwk_priv = {
    "kty": "RSA",
    "n":"mXa2x22fO8ASC7K0LySwedBIO-1xs5r1FLCNHgfu0PmuKoYp9S3zsJtTXR2M2GUfxkiz8ST5dCZ4v7GwpgOmX_eGfxR0STARj23KgnoRehg9RAijmPXxi9-1PVHu_oG3ML5uZ05nZBPQJZgqGXvDCQyVw6tyXgKrWmPXb8eILms",
    "e":"AQAB",
    "d":"P-yeWFYGZRotqifHPHf49tTWsffHS_w5KGQedCrzxKKsdNQr-BArGR6qS_g6Kg19fdfc9I7lRgecdqUqowyUKXAR_CyRNLKcWD2Jy-9yQHZSDZnUvbkW20g-kJ6DDUC0yx-UMbvlQ2GxTKksuNmWnXZS2Z0Dlrs15joGFTr_Rgk"
}
jwk_pub = copy(jwk_priv)
del jwk_pub["d"]


cert = """
MIICBjCCAW+gAwIBAgIBATANBgkqhkiG9w0BAQUFADAxMQswCQYDVQQGEwJVUzEN
MAsGA1UEAxMEYXNkZjETMBEGCSqGSIb3DQEJARMEYXNkZjAeFw0xMzA4MjIyMTMx
NTNaFw0xNDA4MjIyMTMxNTNaMDExCzAJBgNVBAYTAlVTMQ0wCwYDVQQDEwRhc2Rm
MRMwEQYJKoZIhvcNAQkBEwRhc2RmMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKB
gQCZdrbHbZ87wBILsrQvJLB50Eg77XGzmvUUsI0eB+7Q+a4qhin1LfOwm1NdHYzY
ZR/GSLPxJPl0Jni/sbCmA6Zf94Z/FHRJMBGPbcqCehF6GD1ECKOY9fGL37U9Ue7+
gbcwvm5nTmdkE9AlmCoZe8MJDJXDq3JeAqtaY9dvx4guawIDAQABoy4wLDAMBgNV
HRMEBTADAQH/MAsGA1UdDwQEAwIC9DAPBgNVHREECDAGgQRhc2RmMA0GCSqGSIb3
DQEBBQUAA4GBACNbRRnq5utziHBiUAh7z87Mgm9EzsNOz/tYRqbiHYqNpHiYAaCV
0puGCKeB+kU/kIqFI0nQ4aWjZDQmtgPj39oI2EuzL0c+J3ux9NhiE5YIg2Bkrf2z
f56W5ExLLyiBerztpkt430HoDmoK13wBr+nzEX8JIeD+KFvlcizUHEM0
"""

payload = "Shall I compare the to a summer's day?"

# Test sign / verify with jwk
jws1 = jose.sign({ "alg":"RS256", "jwk": jwk_pub }, [jwk_priv], payload )
ver1 = jose.verify(jws1, [])
print jws1
print
print ver1
print

# Test sign / verify with x5c
jws2 = jose.sign({ "alg":"RS256", "x5c": [cert] }, [jwk_priv], payload )
ver2 = jose.verify(jws1, [])
print jws2
print
print ver2
print
