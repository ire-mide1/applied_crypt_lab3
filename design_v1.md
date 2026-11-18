# Crypto Server Client: Design (v1)

Based on `crypto_message_spec_v2.md` (wire format, algorithms) and `Requirements_v2.md` (behaviour). If this document disagrees with either, they win. No code has been written yet.

## 1. Files and their purpose

| File | Purpose |
|---|---|
| `client.py` | The whole app: constants, framing, crypto, validation, file-name helpers, GUI-free operations, and the Tkinter GUI. Importing it must not open a window; the GUI starts only under `if __name__ == "__main__":`. |
| `test_vectors.py` | Plain-assert checks of the spec section 9 vectors. Covers framing, AES (with a fixed nonce, plus a local decrypt of the vector), Ki, Ko, inner hash, both HMAC vectors, and "not the standard HMAC value". Prints a PASS line per check. No network. |
| `fake_server.py` | Local test server on 127.0.0.1. It imports framing and `custom_hmac` from `client.py`. It implements `get_key`, `decrypt` and `verify_hmac` and replies with `error` for anything malformed. It is only for testing the client, so it proves agreement with itself, not correctness. |
| `Results/` | Test files, their `.enc/.key/.dec/.hmac/.hmackey` outputs, `hello_modified.txt`, and three screenshots. |
| `.gitignore` | `__pycache__/` and `*.pyc` only. |
| `Requirements_v2.md`, `crypto_message_spec_v2.md`, `design_v1.md` | Documents. |

## 2. `client.py` structure

The file is a sequence of blocks, each with a short comment. Everything above the GUI block is plain functions that tests and the fake server can import.

### 2.1 Constants

Max payload 1,048,576. Max header 1,000. Encrypt overhead 28 (so max plaintext 1,048,548). Min `.enc` size 28. Timeout 30 s. Default port 8080. Username pattern (1–32 of `A-Za-z0-9_.-`).

### 2.2 Exceptions

Every failure the user should see is raised as one of these, carrying a safe message, so the GUI never shows raw exception text.

| Exception | Meaning |
|---|---|
| `ClientError(message)` | Local problem: bad input, file too big, bad key file, network failure, malformed reply. The message is already user-ready. |
| `ServerError(detail)` | The server replied with `type: error`. Holds the server's `detail` text. |

### 2.3 Framing and network

| Function | What it does |
|---|---|
| `recv_exact(sock, n)` | Loops on `recv` until exactly `n` bytes arrive. Raises `ClientError("Connection closed before the full reply arrived.")` if the peer closes early. |
| `build_message(msg_type, username, extra, payload)` | Builds the full byte string: 4-byte big-endian length, then compact JSON header (`","` and `":"` separators, key order `type`, `username`, `payload_len`, then the extra fields), then the payload. `payload_len` is always set from the payload. |
| `read_message(sock)` | Reads one reply. Reads the 4-byte length and rejects anything over 1,000. Reads and parses the header JSON (must be an object). Checks that `payload_len` is an integer from 0 to 1,048,576. Reads the payload. Any violation raises `ClientError("Unexpected reply from server.")`. Returns `(header, payload)`. |
| `exchange(host, port, msg_type, username, extra, payload)` | One request, one connection: connect with a 30 s timeout, `sendall(build_message(...))`, `read_message`, close. Maps socket exceptions to `ClientError` messages (see section 6). If the reply type is `error`, raises `ServerError(detail)`. |

### 2.4 Crypto

| Function | What it does |
|---|---|
| `sha256(data)` | SHA-256 via `cryptography` `hashes.SHA256` only. Returns 32 bytes. |
| `custom_hmac(key, data)` | Spec section 6: `sha256(Ko + sha256(Ki + data))` with 32-byte `Ki`, `Ko`. No standard HMAC module anywhere. |
| `encrypt_bytes(key, plaintext, nonce=None)` | `nonce` defaults to 12 fresh random bytes. Returns `nonce + AESGCM(key).encrypt(nonce, plaintext, None)`. The `nonce` argument is for tests only; the GUI never passes it. |

### 2.5 Validation and file helpers

| Function | What it does |
|---|---|
| `validate_connection(host, port_text, username)` | Host non-empty; port is a whole number from 1 to 65535; username matches the pattern. Returns `(host, port, username)` or raises `ClientError` with a specific message. |
| `check_size(path, limit, label)` | Raises `ClientError` if the file is over `limit` bytes. The message names the limit. |
| `decode_key_text(text, what)` | Strips whitespace. Strict standard base64 (`validate=True`), must decode to exactly 32 bytes. Raises `ClientError` naming `what`. |
| `read_b64_file(path)` | Reads a `.key`, `.hmac` or `.hmackey` file and runs `decode_key_text`. The error names the file. |
| `write_b64_file(path, raw32)` | Writes standard base64 text with no trailing newline. |
| `key_path_for_enc(enc_path)` | `wave.wav.enc` → `wave.wav.key`. Raises `ClientError("Please pick a .enc file.")` if the suffix is not `.enc`. |
| `original_path_for_enc(enc_path)` | `.enc` removed (`wave.wav`). |
| `dec_name_for_enc(enc_path)` | Removes `.enc`, then inserts `.dec` before the last extension only (`wave.dec.wav`, `a.tar.dec.gz`, `README.dec`, `.bashrc.dec`). A leading dot is not an extension. |
| `hmac_paths(path)` | Returns `path + ".hmac"` and `path + ".hmackey"`. |
| `files_identical(a, b)` | Chunked byte-by-byte comparison. |

### 2.6 Operations (GUI-free)

Each takes already-validated, already-confirmed inputs (overwrite prompts belong to the GUI) and either returns a result or raises `ClientError` / `ServerError`.

| Function | Network | What it does |
|---|---|---|
| `op_get_key(host, port, user)` | yes | Sends `get_key`. Requires a `key_result` reply, decodes its key via `decode_key_text` (invalid → "Server sent an invalid key"). Returns 32 raw bytes. Used for both AES and HMAC keys. |
| `op_encrypt(src, key, enc_out)` | no | Size check, read, `encrypt_bytes`, write `.enc`, write the `.key` beside it. |
| `op_decrypt(host, port, user, enc_path, key)` | yes | Size and minimum-size checks, read file, send `decrypt`, require `decrypt_result`, return the payload bytes. |
| `op_compute_hmac(src, key)` | no | Size check, read, `custom_hmac`, write `.hmac` and `.hmackey` beside the file. |
| `op_verify(host, port, user, path, key, mac)` | yes | Size check, read, send `verify_hmac`, require `verify_result`. Returns `True` for `VERIFIED` and `False` for `FAILED`. Any other value of `result` → "Unexpected reply from server." |

### 2.7 GUI (`App` class)

| Part | What it does |
|---|---|
| `__init__` | Builds the widgets in section 4, creates the two key slots (`aes_key`, `hmac_key`, both initially `None`), a `queue.Queue` for worker results, and a busy flag. |
| `on_operation_change` | Hides the current input frame and shows the one for the selected operation. Does not clear the status line or the key slots. |
| `browse_*` helpers | Open file pickers and fill the matching entry. Browsing for the main file also pre-fills the companion fields when the derived file exists. |
| `set_status(text, kind)` | Sets the single status line. `kind` is `ok` (green), `fail` (red), `error` (black, prefixed `ERROR:`) or `info` (black, no prefix). |
| `set_busy(flag)` | Enables or disables the Run buttons. |
| `run_selected` | Dispatches to one handler per operation. All dialogs and local validation happen here on the main thread, before any worker starts. |
| `start_worker(func, args, on_done)` | Sets busy, starts a `threading.Thread` that runs `func` and puts `("ok", result)` or `("err", exception)` on the queue. The worker never touches a widget. |
| `poll_queue` | Called every 100 ms through `root.after`. When a result arrives, clears busy and calls `on_done` or the error handler on the main thread. |
| `handle_exception(exc)` | The single place that turns any exception into a status line (section 6). |

## 3. Message flow per operation

All network operations use one connection per request: connect, send one message, read one reply, close.

### 3.1 Get AES Key / Get HMAC Key

1. Main thread: `validate_connection`.
2. Worker: `op_get_key` sends `{"type":"get_key","username":U,"payload_len":0}`.
3. Server: `key_result` with a base64 key.
4. Main thread: store the key in the AES slot (or the HMAC slot, depending on the dropdown) and show "AES key received" or "HMAC key received".

### 3.2 Encrypt (local)

1. If the AES slot is empty, show the "get a key first" message and stop.
2. Pick the source file, then check its size (≤ 1,048,548).
3. Save-As dialog with `<name>.enc` filled in. It asks about overwriting the `.enc`.
4. If the `.key` beside it already exists, ask before replacing it.
5. `op_encrypt` writes `.enc` and `.key`. Status: files written.

### 3.3 Decrypt (server)

1. Main thread: `validate_connection`. The `.enc` must end in `.enc`, be ≤ 1,048,576 and ≥ 28 bytes.
2. Resolve the key file: the field if filled, else the derived `.key`, else a picker. Read it with `read_b64_file`.
3. Ask for the output folder. The name comes from `dec_name_for_enc`. Ask before overwriting an existing file.
4. Worker: `op_decrypt` sends `{"type":"decrypt",...,"key":K}` with the `.enc` bytes as payload. The server replies `decrypt_result` with the plaintext as payload.
5. Main thread: write the bytes to the output path. Look for the original next to the `.enc` (`original_path_for_enc`). Report one of the three comparison messages from requirements 5.3.

### 3.4 Compute HMAC (local)

1. If the HMAC slot is empty, show "Get an HMAC key first." and stop.
2. Check the file size (≤ 1,048,576).
3. Ask before replacing an existing `.hmac` or `.hmackey`.
4. `op_compute_hmac` writes both files beside the source. Status: files written.

### 3.5 Verify HMAC (server)

1. Main thread: `validate_connection`. Check the file size (≤ 1,048,576).
2. Resolve the `.hmac` and `.hmackey` files, using the fields, the derived paths, or pickers. Read both with `read_b64_file`.
3. Worker: `op_verify` sends `{"type":"verify_hmac",...,"key":K,"hmac":M}` with the file as payload.
4. Server: `verify_result` with `VERIFIED` or `FAILED`.
5. Main thread: `VERIFIED` → green "HMAC verified by server". `FAILED` → red "HMAC did not match". A well-formed `FAILED` is not an exception.

## 4. GUI layout

The window has three zones: a connection bar (always visible), an operation area (changes), and a status line (always visible).

```
+--------------------------------------------------------------+
| Host/IP: [____________]  Port: [8080]  Username: [________]  |
| Operation: [ Get AES Key  v ]                                |
|--------------------------------------------------------------|
|  (operation area: one of the panels below)                   |
|--------------------------------------------------------------|
| status: single line, coloured by kind                        |
+--------------------------------------------------------------+
```

Operation panels:

| Operation | Contents |
|---|---|
| Get AES Key | Short hint label. `[Run]` |
| Get HMAC Key | Short hint label. `[Run]` |
| Encrypt | `File to encrypt: [______] [Browse]` `[Run]`. Run opens the Save-As dialog. |
| Decrypt | `Encrypted file (.enc): [______] [Browse]` `Key file: [______] [Browse]` (auto-filled when the derived file exists) `[Run]`. Run asks for the output folder. |
| Compute HMAC | `File: [______] [Browse]` `[Run]` |
| Verify HMAC | `File: [______] [Browse]` `HMAC file: [______] [Browse]` `HMAC key file: [______] [Browse]` `[Run]`. Companion fields are auto-filled when the derived files exist. |

Notes: the dropdown is labelled "Operation". The panel for the selected operation is the only one visible. Every Run button is disabled while a network operation runs. Plain Tkinter widgets, no styling.

## 5. Threading model

- Only network calls run in a worker thread. File reads of at most 1 MiB, encryption, HMAC and comparison run on the main thread.
- All dialogs, validation and file reading are done before the worker starts, so the worker only needs plain values.
- The worker communicates only through the queue. The main thread polls it with `root.after(100, ...)` and updates widgets.

## 6. Error handling

Every failure ends as one status line, produced by `handle_exception`. Nothing is shown from raw exception text, and no key, header or request contents appear in any message.

| Situation | Where detected | Status line |
|---|---|---|
| Empty host, bad port, bad username | `validate_connection` (before connecting) | `ERROR:` plus a specific message |
| File over its limit; `.enc` too big or under 28 bytes; not a `.enc` file | `check_size`, `key_path_for_enc`, the decrypt checks | `ERROR:` plus a specific message (for example "Please pick a .enc file.") |
| Key, HMAC or key file missing, bad base64, wrong length | `read_b64_file` / `decode_key_text` | `ERROR:` naming the file and the problem |
| No key held (Encrypt or Compute HMAC) | Run handler | The "get a key first" messages |
| Connect refused, name lookup failure, timeout, reset | `exchange` | `ERROR:` with a plain description of what happened (for example "Timed out waiting for the server"). The cause is not guessed. |
| Connection closed mid-reply | `recv_exact` | `ERROR: Connection closed before the full reply arrived.` |
| Reply header over 1,000, bad JSON, wrong type, `payload_len` invalid or over the cap, wrong `result` value | `read_message` / `op_*` | `ERROR: Unexpected reply from server.` |
| Invalid key from `get_key` | `op_get_key` | `ERROR: Server sent an invalid key` (key not stored) |
| Server `error` reply (any command) | `exchange` raises `ServerError` | `ERROR: The server returned an error. The server does not say why.` followed by the server's detail text (capped at 200 characters, control characters removed) |
| Verify answered `FAILED` | `op_verify` returns `False` | Red "HMAC did not match". Not an exception and no `ERROR:` prefix. |
| Original not found for the comparison | Decrypt handler | Notice, no `ERROR:` prefix |
| File read/write failure (`OSError`) | Operations | `ERROR:` with the file name and the OS's message text |
| Anything unexpected | `handle_exception` catch-all | `ERROR: Unexpected internal error (<exception class name>)`. Only the class name, never the message. |

The program never exits on an error. Busy state is always cleared in a `finally`-style path so the Run buttons cannot stay disabled.

## 7. Testing hooks

| Step | What is exercised | How |
|---|---|---|
| Framing | `build_message` against the section 9 hex; `read_message` on built messages through a socket pair | `test_vectors.py` |
| AES | `encrypt_bytes` with the fixed nonce; local decrypt of the vector | `test_vectors.py` |
| HMAC | Ki, Ko, inner hash, both HMAC vectors, not `411b9a51…` | `test_vectors.py` |
| Operations | All five `op_*` functions and error paths | `fake_server.py` on 127.0.0.1 |
| Real server | `get_key`, decrypt round trip, VERIFIED then FAILED | You run these and report back |

`fake_server.py` serves each connection in its own thread, reuses `client.py` framing and `custom_hmac`, and rejects malformed requests with a generic `error`. To exercise the error paths without the real server, it treats the username `baduser` as unknown (replying `error`) and the username `slowuser` as one that never replies (for the timeout path). These test-only usernames are my proposal.

## 8. Decisions made here

- **Decrypt prompts up front.** I ask for the output folder and the overwrite confirmation before sending the request, so a cancel costs nothing and the rest runs without interaction. The alternative is to ask after the reply arrives.
- **Error detail is shown but capped.** The server's `detail` is shown as the requirements say, truncated to 200 characters with control characters removed.
- **Catch-all shows only the class name.** This satisfies "no exception text" for keys, at the cost of a less helpful message for bugs.
- **Fake-server usernames.** `baduser` and `slowuser` are my proposal for testing error and timeout paths.
