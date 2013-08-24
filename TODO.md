# TODO

In no particular order: 

* Support "jku" / "x5u" (?)
* Support "zip" in JWS (after signature)
* Present key used for verification in result
* Refine crypto API to complete analogy to WebCrypto (with intelligent defaults)


# DONE

* Support "zip"
* Support "crit"
* Add docstrings to polyfills.py
* Add docstrings to josecrypto.py
* Support "jwk"
* Support "x5c"
* Add tests for "jwk" and "x5c"
* Change unserialized format from base64 to binary
* Add Msgpack serialization
* Support "JWP" (or something for unsigned content)
