# Crypto server client: constants, exceptions, framing, AES-GCM, course HMAC,
# base64/key helpers, the three network requests, file-name helpers, file
# reading/writing, the op_* wrappers and the Tkinter GUI.
# Run the GUI with: python crypto_client/client.py

import base64
import binascii
import json
import os
import queue
import re
import socket
import struct
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

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


def check_enc_file(enc_path):
    """Local checks for a file to decrypt: .enc name, 28 bytes to 1 MiB."""
    path = require_enc(enc_path)
    size = check_size(path, MAX_PAYLOAD, "Encrypted file")
    if size < MIN_ENC_SIZE:
        raise ClientError("Not a valid encrypted file (too short)")
    return path


def op_decrypt(host, port, username, enc_path, key):
    """Checks the .enc file locally, sends it to the server, returns plaintext."""
    path = check_enc_file(enc_path)
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


# ------------------------------------------------------------------------ GUI
class Cancelled(Exception):
    """The user closed a dialog or answered No. Not an error."""


def validate_connection(host, port_text, username):
    """Check the connection fields locally. Returns (host, port, username)."""
    if not host:
        raise ClientError("Enter the server host or IP address.")
    if not (port_text.isdigit() and 1 <= int(port_text) <= 65535):
        raise ClientError("The port must be a whole number from 1 to 65535.")
    if not USERNAME_RE.fullmatch(username):
        raise ClientError("The username must be 1-32 characters from A-Z a-z 0-9 _ . -")
    return host, int(port_text), username


ALL_FILES = ("All files", "*.*")
OPERATIONS = ["Get AES Key", "Encrypt", "Decrypt", "Get HMAC Key", "Compute HMAC", "Verify HMAC"]
# For each operation: a hint, and its file fields as (key, label, file types).
PANELS = {
    "Get AES Key": ("Gets a new AES key from the server and keeps it in memory.", []),
    "Encrypt": ("Encrypts a file locally with the AES key. Run asks where to save it.",
                [("src", "File to encrypt:", [ALL_FILES])]),
    "Decrypt": ("Sends an encrypted file and its key to the server. The key file is found "
                "automatically if it sits beside the .enc file. Run asks for the output folder.",
                [("enc", "Encrypted file (.enc):", [("Encrypted files", "*.enc"), ALL_FILES]),
                 ("key", "Key file (.key):", [("Key files", "*.key"), ALL_FILES])]),
    "Get HMAC Key": ("Gets a new key from the server and keeps it in memory as the HMAC key.", []),
    "Compute HMAC": ("Computes the HMAC of a file locally with the HMAC key.",
                     [("src", "File:", [ALL_FILES])]),
    "Verify HMAC": ("Sends a file, its key and its HMAC to the server. The .hmac and .hmackey "
                    "files are found automatically if they sit beside the file.",
                    [("src", "File:", [ALL_FILES]),
                     ("hmac", "HMAC file (.hmac):", [("HMAC files", "*.hmac"), ALL_FILES]),
                     ("hmackey", "HMAC key file (.hmackey):",
                      [("HMAC key files", "*.hmackey"), ALL_FILES])]),
}
STATUS_COLOURS = {"verified": "#008000", "failed": "#cc0000", "error": "black", "info": "black"}


class App:
    def __init__(self, root):
        self.root = root
        self.aes_key = None            # two separate key slots, kept in memory only
        self.hmac_key = None
        self.busy = False
        self.results = queue.Queue()   # worker thread -> main thread
        self.handlers = {
            "Get AES Key": lambda: self.do_get_key("aes"),
            "Encrypt": self.do_encrypt,
            "Decrypt": self.do_decrypt,
            "Get HMAC Key": lambda: self.do_get_key("hmac"),
            "Compute HMAC": self.do_compute_hmac,
            "Verify HMAC": self.do_verify,
        }
        root.title("Crypto Server Client")
        root.minsize(640, 260)

        # connection bar and operation dropdown
        bar = tk.Frame(root)
        bar.pack(fill="x", padx=8, pady=(8, 2))
        self.host = tk.StringVar()
        self.port = tk.StringVar(value=str(DEFAULT_PORT))
        self.user = tk.StringVar()
        tk.Label(bar, text="Host/IP:").grid(row=0, column=0, sticky="e")
        tk.Entry(bar, textvariable=self.host, width=24).grid(row=0, column=1, padx=(2, 10))
        tk.Label(bar, text="Port:").grid(row=0, column=2, sticky="e")
        tk.Entry(bar, textvariable=self.port, width=7).grid(row=0, column=3, padx=(2, 10))
        tk.Label(bar, text="Username:").grid(row=0, column=4, sticky="e")
        tk.Entry(bar, textvariable=self.user, width=18).grid(row=0, column=5, padx=2)
        self.operation = tk.StringVar(value=OPERATIONS[0])
        tk.Label(bar, text="Operation:").grid(row=1, column=0, sticky="e", pady=(8, 0))
        combo = ttk.Combobox(bar, textvariable=self.operation, values=OPERATIONS,
                             state="readonly", width=22)
        combo.grid(row=1, column=1, columnspan=2, sticky="w", padx=(2, 10), pady=(8, 0))
        combo.bind("<<ComboboxSelected>>", lambda event: self.on_operation_change())

        # one panel per operation; only the selected one is shown
        self.op_area = tk.Frame(root)
        self.op_area.pack(fill="x", padx=8, pady=8)
        self.panels = {}
        self.vars = {}
        self.run_buttons = []
        for op in OPERATIONS:
            self.panels[op] = self.build_panel(op)
        self.current = None
        self.on_operation_change()

        # status line
        self.status = tk.Label(root, text="", anchor="w", justify="left", wraplength=620)
        self.status.pack(fill="x", side="bottom", padx=8, pady=8)

        self.root.after(100, self.poll_queue)

    def build_panel(self, op):
        hint, fields = PANELS[op]
        panel = tk.Frame(self.op_area)
        tk.Label(panel, text=hint, anchor="w", justify="left",
                 wraplength=600).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 6))
        row = 1
        for key, label, filetypes in fields:
            var = tk.StringVar()
            self.vars[(op, key)] = var
            tk.Label(panel, text=label).grid(row=row, column=0, sticky="e")
            tk.Entry(panel, textvariable=var, width=52).grid(row=row, column=1, padx=4, pady=2)
            tk.Button(panel, text="Browse...",
                      command=lambda o=op, k=key, t=filetypes, l=label: self.browse(o, k, t, l)
                      ).grid(row=row, column=2)
            row += 1
        run = tk.Button(panel, text="Run", width=10, command=self.run_selected)
        run.grid(row=row, column=1, sticky="w", padx=4, pady=(8, 0))
        self.run_buttons.append(run)
        return panel

    def on_operation_change(self):
        if self.current is not None:
            self.panels[self.current].pack_forget()
        self.current = self.operation.get()
        self.panels[self.current].pack(fill="x")

    # --- status, busy state, errors
    def set_status(self, text, kind="info"):
        if kind == "error":
            text = "ERROR: " + text
        self.status.config(text=text, fg=STATUS_COLOURS[kind])

    def set_busy(self, busy):
        self.busy = busy
        for button in self.run_buttons:
            button.config(state="disabled" if busy else "normal")

    def handle_exception(self, exc):
        """The one place that turns an exception into a status line. Never
        shows raw exception text, so no key or request content can leak."""
        if isinstance(exc, Cancelled):
            self.set_status("Cancelled.", "info")
        elif isinstance(exc, ServerError):
            text = "Server returned an error"
            if exc.detail:
                text += " (%s)" % exc.detail
            self.set_status(text, "error")
        elif isinstance(exc, ClientError):
            self.set_status(str(exc), "error")
        else:
            self.set_status("Unexpected internal error (%s)" % type(exc).__name__, "error")

    # --- worker thread
    def start_worker(self, func, args, on_done):
        """Run func(*args) off the main thread. on_done(result) runs back on
        the main thread. The worker never touches a widget."""
        self.set_busy(True)
        self.set_status("Contacting the server...", "info")

        def work():
            try:
                self.results.put(("ok", func(*args), on_done))
            except Exception as exc:
                self.results.put(("err", exc, None))

        threading.Thread(target=work, daemon=True).start()

    def poll_queue(self):
        try:
            while True:
                state, value, on_done = self.results.get_nowait()
                self.set_busy(False)
                try:
                    if state == "ok":
                        on_done(value)
                    else:
                        self.handle_exception(value)
                except Exception as exc:
                    self.handle_exception(exc)
        except queue.Empty:
            pass
        self.root.after(100, self.poll_queue)

    # --- helpers for the handlers (main thread)
    def run_selected(self):
        if self.busy:
            return
        try:
            self.handlers[self.operation.get()]()
        except Exception as exc:
            self.handle_exception(exc)

    def connection(self):
        return validate_connection(self.host.get().strip(), self.port.get().strip(),
                                   self.user.get().strip())

    def field_text(self, op, key):
        return self.vars[(op, key)].get().strip().strip('"')

    def path(self, op, key, message):
        text = self.field_text(op, key)
        if not text:
            raise ClientError(message)
        return Path(text)

    def browse(self, op, key, filetypes, label):
        chosen = filedialog.askopenfilename(title="Select " + label.rstrip(":"),
                                            filetypes=filetypes)
        if not chosen:
            return
        self.vars[(op, key)].set(chosen)
        # fill in the companion files when they sit beside the chosen file
        try:
            if (op, key) == ("Decrypt", "enc"):
                companions = {"key": key_path_for_enc(chosen)}
            elif (op, key) == ("Verify HMAC", "src"):
                companions = dict(zip(("hmac", "hmackey"), hmac_paths(chosen)))
            else:
                return
        except ClientError:                      # not a .enc file: Run will say so
            companions = {"key": None}
        for name, companion in companions.items():
            found = companion is not None and companion.is_file()
            self.vars[(op, name)].set(str(companion) if found else "")

    def resolve_file(self, op, key, derived, title):
        """The file in the field, else the derived companion if it exists,
        else a file picker."""
        text = self.field_text(op, key)
        if text:
            return Path(text)
        if derived.is_file():
            return derived
        chosen = filedialog.askopenfilename(title=title, initialdir=str(derived.parent))
        if not chosen:
            raise Cancelled()
        return Path(chosen)

    def confirm_replace(self, paths, note=""):
        existing = [p for p in paths if p.exists()]
        if not existing:
            return
        text = "These files already exist:\n" + "\n".join(p.name for p in existing)
        text += "\n\nReplace them?" + (("\n\n" + note) if note else "")
        if not messagebox.askyesno("Replace existing file?", text, icon="warning"):
            raise Cancelled()

    # --- operations
    def do_get_key(self, slot):
        host, port, user = self.connection()

        def done(key):
            if slot == "aes":
                self.aes_key = key
                self.set_status("AES key received", "info")
            else:
                self.hmac_key = key
                self.set_status("HMAC key received", "info")

        self.start_worker(request_get_key, (host, port, user), done)

    def do_encrypt(self):
        if self.aes_key is None:
            raise ClientError("Get an AES key first.")
        src = self.path("Encrypt", "src", "Choose a file to encrypt.")
        check_size(src, MAX_PLAINTEXT, "File to encrypt")
        chosen = filedialog.asksaveasfilename(
            title="Save the encrypted file as", initialdir=str(src.parent),
            initialfile=enc_path_for_original(src).name, defaultextension=ENC_SUFFIX,
            filetypes=[("Encrypted files", "*.enc")])
        if not chosen:
            raise Cancelled()
        enc_out = Path(chosen)
        if not _is_enc_name(enc_out.name):       # force .enc
            enc_out = enc_out.with_name(enc_out.name + ENC_SUFFIX)
            self.confirm_replace([enc_out])      # the dialog did not ask about this name
        self.confirm_replace(
            [key_path_for_enc(enc_out)],
            "Replacing a key file makes the .enc file that used it impossible to decrypt.")
        enc_out, key_path = op_encrypt(src, self.aes_key, enc_out)
        self.set_status("Encrypted. Wrote %s and %s." % (enc_out.name, key_path.name), "info")

    def do_decrypt(self):
        host, port, user = self.connection()
        enc = check_enc_file(self.path("Decrypt", "enc", "Choose a .enc file to decrypt."))
        key_file = self.resolve_file("Decrypt", "key", key_path_for_enc(enc),
                                     "Select the key file")
        key = read_b64_file(key_file)
        folder = filedialog.askdirectory(title="Choose the folder for the decrypted file",
                                         initialdir=str(enc.parent))
        if not folder:
            raise Cancelled()
        out_path = decrypted_output_path(enc, folder)
        self.confirm_replace([out_path])

        def done(plaintext):
            saved = write_decrypted(plaintext, enc, folder)
            result, message = compare_with_original(enc, saved)
            self.set_status("Saved %s. %s" % (saved.name, message),
                            "error" if result is False else "info")

        self.start_worker(op_decrypt, (host, port, user, enc, key), done)

    def do_compute_hmac(self):
        if self.hmac_key is None:
            raise ClientError("Get an HMAC key first.")
        src = self.path("Compute HMAC", "src", "Choose a file.")
        check_size(src, MAX_PAYLOAD, "File")
        self.confirm_replace(list(hmac_paths(src)))
        _, hmac_path, hmackey_path = op_compute_hmac(src, self.hmac_key)
        self.set_status("HMAC computed. Wrote %s and %s." % (hmac_path.name, hmackey_path.name),
                        "info")

    def do_verify(self):
        host, port, user = self.connection()
        src = self.path("Verify HMAC", "src", "Choose the file to verify.")
        check_size(src, MAX_PAYLOAD, "File")
        hmac_default, hmackey_default = hmac_paths(src)
        hmac_file = self.resolve_file("Verify HMAC", "hmac", hmac_default, "Select the .hmac file")
        hmackey_file = self.resolve_file("Verify HMAC", "hmackey", hmackey_default,
                                         "Select the .hmackey file")
        mac = read_b64_file(hmac_file)
        key = read_b64_file(hmackey_file)

        def done(verified):
            if verified:
                self.set_status("HMAC verified by server", "verified")
            else:
                self.set_status("HMAC did not match", "failed")

        self.start_worker(op_verify, (host, port, user, src, key, mac), done)


def main():
    root = tk.Tk()
    App(root)
    root.mainloop()


if __name__ == "__main__":
    main()
