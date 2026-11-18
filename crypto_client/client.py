# Crypto server client. So far: constants, exceptions, framing, AES-GCM,
# course HMAC, base64/key helpers, the three network requests, file-name
# helpers, file reading/writing and the op_* wrappers. No GUI yet.

import base64
import binascii
import json
import os
import re
import socket
import struct
from pathlib import Path

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


# ------------------------------------------------------------------ network
def _clean_detail(detail):
    """Server error text made safe to show: printable characters, max 200."""
    if not isinstance(detail, str):
        return ""
    return "".join(ch for ch in detail if ch.isprintable())[:200]


def exchange(host, port, msg_type, username, extra, payload, expect):
    """One request on one connection. Returns (reply header, reply payload).

    Raises ServerError for an "error" reply and ClientError for anything else
    that goes wrong, including a reply whose type is not `expect`.
    """
    message = build_message(msg_type, username, extra, payload)
    try:
        with socket.create_connection((host, port), timeout=TIMEOUT) as sock:
            sock.sendall(message)
            header, data = read_message(sock)
    except socket.timeout:
        raise ClientError("Timed out waiting for the server.") from None
    except socket.gaierror:
        raise ClientError("Could not look up the server name.") from None
    except ConnectionRefusedError:
        raise ClientError("Connection refused by the server address.") from None
    except ConnectionError:
        raise ClientError("Connection was reset.") from None
    except OSError as exc:
        raise ClientError("Network error: %s" % (exc.strerror or type(exc).__name__)) from None
    reply_type = header.get("type")
    if reply_type == "error":
        raise ServerError(_clean_detail(header.get("detail")))
    if reply_type != expect:
        raise ClientError(UNEXPECTED_REPLY)
    return header, data


def request_get_key(host, port, username):
    """Send get_key. Returns the new 32-byte key, or raises."""
    header, _ = exchange(host, port, "get_key", username, None, b"", "key_result")
    try:
        return decode_key_text(header.get("key"), "Server key")
    except (ClientError, AttributeError):
        raise ClientError("Server sent an invalid key") from None


def request_decrypt(host, port, username, key, blob):
    """Send decrypt with the encrypted file bytes. Returns the plaintext."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    if len(blob) < MIN_ENC_SIZE:
        raise ClientError("Not a valid encrypted file (too short)")
    if len(blob) > MAX_PAYLOAD:
        raise ClientError("Encrypted file is larger than %d bytes." % MAX_PAYLOAD)
    _, data = exchange(host, port, "decrypt", username,
                       {"key": encode_b64(key)}, blob, "decrypt_result")
    return data


def request_verify(host, port, username, key, mac, data):
    """Send verify_hmac. Returns True for VERIFIED, False for FAILED."""
    if len(key) != KEY_LEN or len(mac) != KEY_LEN:
        raise ValueError("key and hmac must be 32 bytes")
    if len(data) > MAX_PAYLOAD:
        raise ClientError("File is larger than %d bytes." % MAX_PAYLOAD)
    header, _ = exchange(host, port, "verify_hmac", username,
                         {"key": encode_b64(key), "hmac": encode_b64(mac)},
                         data, "verify_result")
    result = header.get("result")
    if result == "VERIFIED":
        return True
    if result == "FAILED":
        return False
    raise ClientError(UNEXPECTED_REPLY)


# ---------------------------------------------------------------- file names
ENC_SUFFIX = ".enc"


def _is_enc_name(name):
    return name.endswith(ENC_SUFFIX) and len(name) > len(ENC_SUFFIX)


def require_enc(enc_path):
    """Return enc_path as a Path, or refuse it if it is not a .enc file."""
    path = Path(enc_path)
    if not _is_enc_name(path.name):
        raise ClientError("Please pick a .enc file.")
    return path


def enc_path_for_original(path):
    """wave.wav -> wave.wav.enc (default name for the encrypted file)."""
    path = Path(path)
    return path.with_name(path.name + ENC_SUFFIX)


def key_path_for_enc(enc_path):
    """wave.wav.enc -> wave.wav.key (remove .enc, add .key)."""
    path = require_enc(enc_path)
    return path.with_name(path.name[:-len(ENC_SUFFIX)] + ".key")


def original_path_for_enc(enc_path):
    """wave.wav.enc -> wave.wav (remove .enc)."""
    path = require_enc(enc_path)
    return path.with_name(path.name[:-len(ENC_SUFFIX)])


def dec_name_for_enc(enc_path):
    """Name for the decrypted file: remove .enc, insert .dec before the last
    extension only. A leading dot is not an extension.
    wave.wav.enc -> wave.dec.wav, a.tar.gz.enc -> a.tar.dec.gz,
    README.enc -> README.dec, .bashrc.enc -> .bashrc.dec
    """
    name = original_path_for_enc(enc_path).name
    dot = name.rfind(".")
    if dot <= 0:
        return name + ".dec"
    return name[:dot] + ".dec" + name[dot:]


def decrypted_output_path(enc_path, out_dir):
    """Where the decrypted file goes: the chosen folder plus the .dec name."""
    return Path(out_dir) / dec_name_for_enc(enc_path)


def hmac_paths(path):
    """wave.wav -> (wave.wav.hmac, wave.wav.hmackey)."""
    path = Path(path)
    return path.with_name(path.name + ".hmac"), path.with_name(path.name + ".hmackey")


# ------------------------------------------------------- file read and write
def _os_message(action, path, exc):
    return "%s %s: %s" % (action, Path(path).name, exc.strerror or type(exc).__name__)


def check_size(path, limit, label):
    """Refuse a file over `limit` bytes. Returns its size."""
    try:
        size = Path(path).stat().st_size
    except OSError as exc:
        raise ClientError(_os_message("Cannot read", path, exc)) from None
    if size > limit:
        raise ClientError("%s is larger than %s bytes." % (label, format(limit, ",")))
    return size


def _read_bytes(path):
    try:
        return Path(path).read_bytes()
    except OSError as exc:
        raise ClientError(_os_message("Cannot read", path, exc)) from None


def _write_bytes(path, data):
    try:
        Path(path).write_bytes(data)
    except OSError as exc:
        raise ClientError(_os_message("Cannot write", path, exc)) from None


def read_input_file(path, limit, label):
    """Check the size first, then read the whole file."""
    check_size(path, limit, label)
    return _read_bytes(path)


def write_b64_file(path, raw):
    """Write raw bytes as standard base64 text with no trailing newline."""
    _write_bytes(path, encode_b64(raw).encode("ascii"))


def read_b64_file(path):
    """Read a .key, .hmac or .hmackey file. Strips surrounding whitespace and
    requires strict standard base64 that decodes to exactly 32 bytes."""
    return decode_key_text(_read_bytes(path), "File " + Path(path).name)


def files_identical(path_a, path_b):
    """Byte-by-byte comparison, in chunks."""
    if Path(path_a).stat().st_size != Path(path_b).stat().st_size:
        return False
    with open(path_a, "rb") as fa, open(path_b, "rb") as fb:
        while True:
            a, b = fa.read(65536), fb.read(65536)
            if a != b:
                return False
            if not a:
                return True


def compare_with_original(enc_path, dec_path):
    """Compare the decrypted file with the original next to the .enc file
    (the .enc name with .enc removed). Returns (result, message): result is
    True (match), False (no match) or None (original not found)."""
    original = original_path_for_enc(enc_path)
    if not original.is_file():
        return None, "Original not found next to the .enc file, comparison skipped."
    try:
        same = files_identical(original, dec_path)
    except OSError as exc:
        raise ClientError(_os_message("Cannot read", exc.filename or original, exc)) from None
    if same:
        return True, "Decrypted file matches the original byte for byte."
    return False, "Decrypted file does NOT match the original."


# ----------------------------------------------------------------- operations
# Overwrite questions belong to the GUI: these functions write what they are
# given. Keys and HMACs come in as raw bytes, already read and validated.
def op_encrypt(src, key, enc_out):
    """Encrypt src to enc_out and write the key beside it as <name>.key.
    Returns (enc path, key path)."""
    enc_out = Path(enc_out)
    if not _is_enc_name(enc_out.name):
        raise ClientError("The output file name must end in .enc.")
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    data = read_input_file(src, MAX_PLAINTEXT, "File to encrypt")
    _write_bytes(enc_out, encrypt_bytes(key, data))
    key_path = key_path_for_enc(enc_out)
    write_b64_file(key_path, key)
    return enc_out, key_path


def op_decrypt(host, port, username, enc_path, key):
    """Checks the .enc file locally, sends it to the server, returns plaintext."""
    path = require_enc(enc_path)
    size = check_size(path, MAX_PAYLOAD, "Encrypted file")
    if size < MIN_ENC_SIZE:
        raise ClientError("Not a valid encrypted file (too short)")
    return request_decrypt(host, port, username, key, _read_bytes(path))


def write_decrypted(plaintext, enc_path, out_dir):
    """Save decrypted bytes as <out_dir>/<.dec name>. Returns the path."""
    out_path = decrypted_output_path(enc_path, out_dir)
    _write_bytes(out_path, plaintext)
    return out_path


def op_compute_hmac(src, key):
    """Compute the course HMAC of src and write <src>.hmac and <src>.hmackey.
    Returns (mac, hmac path, hmackey path)."""
    if len(key) != KEY_LEN:
        raise ValueError("key must be 32 bytes")
    data = read_input_file(src, MAX_PAYLOAD, "File")
    mac = custom_hmac(key, data)
    hmac_path, hmackey_path = hmac_paths(src)
    write_b64_file(hmac_path, mac)
    write_b64_file(hmackey_path, key)
    return mac, hmac_path, hmackey_path


def op_verify(host, port, username, path, key, mac):
    """Checks the file locally, sends it to the server. True = VERIFIED."""
    data = read_input_file(path, MAX_PAYLOAD, "File")
    return request_verify(host, port, username, key, mac, data)
