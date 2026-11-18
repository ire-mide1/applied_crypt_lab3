# Checks client.py against the spec section 9 test vectors. No network.
# Run: python crypto_client/test_vectors.py

import client

KEY = bytes(range(32))
KEY_B64 = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
NONCE = bytes(range(12))
HELLO = b"hello world"


def passed(name):
    print("PASS  " + name)


# --- framing -------------------------------------------------------------
FRAMING_HEX = (
    "000000397b2274797065223a226765745f6b6579222c22757365726e616d65223a22"
    "73747564656e743031222c227061796c6f61645f6c656e223a307d"
)
msg = client.build_message("get_key", "student01")
assert msg.hex() == FRAMING_HEX, "framing differs: " + msg.hex()
assert msg[4:] == b'{"type":"get_key","username":"student01","payload_len":0}'
assert len(msg[4:]) == 57 and msg[:4] == bytes.fromhex("00000039")
passed("framing: get_key message matches the section 9 hex")

# --- AES-GCM -------------------------------------------------------------
ENC_HEX = "000102030405060708090a0b2f67ba77aac5b574ff2df305301c56437e2377b98ef3961c271928"
assert client.encode_b64(KEY) == KEY_B64
blob = client.encrypt_bytes(KEY, HELLO, nonce=NONCE)
assert len(blob) == 39
assert blob.hex() == ENC_HEX, "AES output differs: " + blob.hex()
passed("AES-GCM: encrypt hello world gives the 39-byte vector")

assert client.decrypt_bytes(KEY, bytes.fromhex(ENC_HEX)) == HELLO
passed("AES-GCM: vector decrypts locally to hello world")

# --- course HMAC ---------------------------------------------------------
KI_HEX = "36373435323330313e3f3c3d3a3b383926272425222320212e2f2c2d2a2b2829"
KO_HEX = "5c5d5e5f58595a5b54555657505152534c4d4e4f48494a4b4445464740414243"
INNER_HEX = "05001c1f5260531db22d744e1629e7450903558c545cdd514bea3f555684deac"
HMAC_HEX = "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e"
HMAC_B64 = "WFxl5t64uHbtdCIsWWQGDnBxkt+M6bkbYZjeFz+//y4="
EMPTY_HEX = "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3"
STANDARD_HEX = "411b9a51e8565e1fc79643b2a6c4672f4a3c3e573c33d0995a08748cb6128e8e"

ki, ko = client.derive_keys(KEY)
assert ki.hex() == KI_HEX, "Ki differs: " + ki.hex()
passed("HMAC: Ki")
assert ko.hex() == KO_HEX, "Ko differs: " + ko.hex()
passed("HMAC: Ko")

inner = client.sha256(ki + HELLO)
assert inner.hex() == INNER_HEX, "inner hash differs: " + inner.hex()
passed("HMAC: inner hash for hello world")

mac = client.custom_hmac(KEY, HELLO)
assert mac.hex() == HMAC_HEX, "HMAC differs: " + mac.hex()
assert client.encode_b64(mac) == HMAC_B64
passed("HMAC: hello world (hex and base64)")

empty = client.custom_hmac(KEY, b"")
assert empty.hex() == EMPTY_HEX, "empty-file HMAC differs: " + empty.hex()
passed("HMAC: empty file")

assert mac.hex() != STANDARD_HEX
passed("HMAC: is not the standard-HMAC value 411b9a51...")

print("\nAll checks passed.")
