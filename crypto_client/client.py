# Crypto server client. This stage: constants, exceptions, framing, AES-GCM,
# course HMAC and base64/key helpers. No networking calls, no GUI yet.

import base64
import binascii
import json
import os
import re
import struct

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# ---------------------------------------------------------------- constants
MAX_PAYLOAD = 1_048_576          # largest payload either way (1 MiB)
MAX_HEADER = 1000                # largest JSON header in bytes
NONCE_LEN = 12
TAG_LEN = 16
ENC_OVERHEAD = NONCE_LEN + TAG_LEN       # 28
MAX_PLAINTEXT = MAX_PAYLOAD - ENC_OVERHEAD   # 1,048,548
MIN_ENC_SIZE = ENC_OVERHEAD
KEY_LEN = 32
TIMEOUT = 30                     # seconds, connect and read
DEFAULT_PORT = 8080
USERNAME_RE = re.compile(r"[A-Za-z0-9_.\-]{1,32}")
UNEXPECTED_REPLY = "Unexpected reply from server."


# --------------------------------------------------------------- exceptions
class ClientError(Exception):
    """Local problem. The message is already safe and ready to show."""


class ServerError(Exception):
    """The server replied with type "error". Holds its detail text."""

    def __init__(self, detail=""):
        super().__init__(detail)
        self.detail = detail


# ------------------------------------------------------------------ framing
def recv_exact(sock, n):
    """Read exactly n bytes from sock, looping until they all arrive."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ClientError("Connection closed before the full reply arrived.")
        buf += chunk
    return bytes(buf)


def build_message(msg_type, username, extra=None, payload=b""):
    """Build one full message: 4-byte big-endian length, compact JSON, payload.

    Header key order: type, username, payload_len, then the extra fields.
    """
    header = {"type": msg_type, "username": username, "payload_len": len(payload)}
    if extra:
        header.update(extra)
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    if len(header_bytes) > MAX_HEADER:
        raise ClientError("Request header is longer than %d bytes." % MAX_HEADER)
    return struct.pack(">I", len(header_bytes)) + header_bytes + payload


def read_message(sock):
    """Read one reply from sock. Returns (header dict, payload bytes)."""
    (header_len,) = struct.unpack(">I", recv_exact(sock, 4))
    if header_len > MAX_HEADER:
        raise ClientError(UNEXPECTED_REPLY)
    try:
        header = json.loads(recv_exact(sock, header_len).decode("utf-8"))
    except (UnicodeDecodeError, ValueError):
        raise ClientError(UNEXPECTED_REPLY) from None
    if not isinstance(header, dict):
        raise ClientError(UNEXPECTED_REPLY)
    payload_len = header.get("payload_len", 0)
    if (not isinstance(payload_len, int) or isinstance(payload_len, bool)
            or payload_len < 0 or payload_len > MAX_PAYLOAD):
        raise ClientError(UNEXPECTED_REPLY)
    return header, recv_exact(sock, payload_len)


# ------------------------------------------------------------------- AES-GCM
def encrypt_bytes(key, plaintext, nonce=None):
    """Return nonce | ciphertext | tag. The nonce argument is for tests only."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if nonce is None:
        nonce = os.urandom(NONCE_LEN)
    elif len(nonce) != NONCE_LEN:
        raise ValueError("nonce must be 12 bytes")
    return nonce + AESGCM(key).encrypt(nonce, plaintext, None)


def decrypt_bytes(key, blob):
    """Local inverse of encrypt_bytes. Raises ClientError on a bad blob."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(blob) < MIN_ENC_SIZE:
        raise ClientError("Not a valid encrypted file (too short)")
    try:
        return AESGCM(key).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], None)
    except InvalidTag:
        raise ClientError("Decryption failed: authentication tag did not match.") from None


# -------------------------------------------------------------- course HMAC
def sha256(data):
    """SHA-256 digest (32 raw bytes) using the cryptography library."""
    h = hashes.Hash(hashes.SHA256())
    h.update(data)
    return h.finalize()


def derive_keys(key):
    """Return (Ki, Ko): K XOR 0x36 and K XOR 0x5C, both 32 bytes, no padding."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    return bytes(b ^ 0x36 for b in key), bytes(b ^ 0x5C for b in key)


def custom_hmac(key, data):
    """Course HMAC (not RFC 2104): SHA-256(Ko || SHA-256(Ki || data))."""
    ki, ko = derive_keys(key)
    return sha256(ko + sha256(ki + data))


# ------------------------------------------------- base64 and key validation
def encode_b64(raw):
    """Standard base64 with padding, as text."""
    return base64.b64encode(raw).decode("ascii")


def decode_key_text(text, what):
    """Strip whitespace, require strict standard base64 of exactly 32 bytes.

    `what` names the thing being checked (for example a file name) so the
    error says where the problem is. Never includes the text itself.
    """
    if isinstance(text, (bytes, bytearray)):
        try:
            text = bytes(text).decode("ascii")
        except UnicodeDecodeError:
            raise ClientError("%s is not valid standard base64." % what) from None
    text = text.strip()
    try:
        raw = base64.b64decode(text, validate=True)
    except (binascii.Error, ValueError):
        raise ClientError("%s is not valid standard base64." % what) from None
    if base64.b64encode(raw).decode("ascii") != text:
        raise ClientError("%s is not valid standard base64." % what)
    if len(raw) != KEY_LEN:
        raise ClientError(
            "%s does not decode to exactly 32 bytes (got %d)." % (what, len(raw)))
    return raw
