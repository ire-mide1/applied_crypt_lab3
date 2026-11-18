# Tests file naming, file reading/writing and the local checks of the op_*
# wrappers, using files in a temporary folder. No network.
# Run: python crypto_client/test_files.py

import tempfile
from pathlib import Path

import client

KEY = bytes(range(32))
HELLO = b"hello world"
MAC = bytes.fromhex("585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e")
# These calls must fail before any connection is tried, so the address is unused.
NET = ("unused.invalid", 1, "user")


def passed(name):
    print("PASS  " + name)


def refused(call, message):
    """Assert that call() raises ClientError with exactly this message."""
    try:
        call()
    except client.ClientError as exc:
        assert str(exc) == message, "got %r, expected %r" % (str(exc), message)
        return
    raise AssertionError("expected ClientError: " + message)


# ---- naming rules ---------------------------------------------------------
assert client.key_path_for_enc("d/wave.wav.enc") == Path("d/wave.wav.key")
assert client.original_path_for_enc("d/wave.wav.enc") == Path("d/wave.wav")
assert client.enc_path_for_original("d/wave.wav") == Path("d/wave.wav.enc")
passed("naming: wave.wav -> wave.wav.enc, wave.wav.key (and back)")

for enc, dec in (("wave.wav.enc", "wave.dec.wav"), ("a.tar.gz.enc", "a.tar.dec.gz"),
                 ("README.enc", "README.dec"), (".bashrc.enc", ".bashrc.dec")):
    assert client.dec_name_for_enc(enc) == dec, (enc, client.dec_name_for_enc(enc))
passed("naming: .dec rules (wave.dec.wav, a.tar.dec.gz, README.dec, .bashrc.dec)")

assert client.decrypted_output_path("in/wave.wav.enc", "out") == Path("out/wave.dec.wav")
assert client.hmac_paths("d/wave.wav") == (Path("d/wave.wav.hmac"), Path("d/wave.wav.hmackey"))
passed("naming: decrypted output path and .hmac / .hmackey paths")

for bad in ("wave.wav", "wave.enc.txt", ".enc", "wave.wav.ENC"):
    refused(lambda: client.key_path_for_enc(bad), "Please pick a .enc file.")
passed("naming: non-.enc files are refused")

with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)

    # ---- base64 files: write without newline, read with whitespace stripped
    keyfile = tmp / "k.key"
    client.write_b64_file(keyfile, KEY)
    raw = keyfile.read_bytes()
    assert raw == b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=" and not raw.endswith(b"\n")
    assert client.read_b64_file(keyfile) == KEY
    passed("base64 file: written as 44 characters, no trailing newline")

    keyfile.write_bytes(b"  \r\n" + raw + b"\r\n\t ")
    assert client.read_b64_file(keyfile) == KEY
    passed("base64 file: surrounding whitespace is stripped when reading")

    keyfile.write_bytes(b"not base64 !!")
    refused(lambda: client.read_b64_file(keyfile), "File k.key is not valid standard base64.")
    keyfile.write_bytes(raw.replace(b"+", b"-").replace(b"/", b"_") if b"+" in raw or b"/" in raw
                        else client.encode_b64(bytes([0xFB] * 32)).replace("+", "-").encode())
    refused(lambda: client.read_b64_file(keyfile), "File k.key is not valid standard base64.")
    keyfile.write_bytes(client.encode_b64(bytes(16)).encode())
    refused(lambda: client.read_b64_file(keyfile),
            "File k.key does not decode to exactly 32 bytes (got 16).")
    keyfile.write_bytes(b"")
    refused(lambda: client.read_b64_file(keyfile),
            "File k.key does not decode to exactly 32 bytes (got 0).")
    passed("base64 file: bad base64, URL-safe characters and wrong length are refused")

    try:
        client.read_b64_file(tmp / "missing.key")
    except client.ClientError as exc:
        assert str(exc).startswith("Cannot read missing.key")
    else:
        raise AssertionError("missing file was not refused")
    passed("base64 file: a missing file gives a ClientError")

    # ---- size checks ------------------------------------------------------
    hello = tmp / "hello.txt"
    hello.write_bytes(HELLO)

    exact = tmp / "exact.bin"
    exact.write_bytes(bytes(client.MAX_PLAINTEXT))            # 1,048,548 bytes
    over = tmp / "over.bin"
    over.write_bytes(bytes(client.MAX_PLAINTEXT + 1))         # 1,048,549 bytes
    assert client.check_size(exact, client.MAX_PLAINTEXT, "File") == client.MAX_PLAINTEXT
    refused(lambda: client.check_size(over, client.MAX_PLAINTEXT, "File"),
            "File is larger than 1,048,548 bytes.")
    passed("size: limit itself is allowed, one byte over is refused")

    # ---- encrypt ----------------------------------------------------------
    enc, keyp = client.op_encrypt(hello, KEY, tmp / "hello.txt.enc")
    assert enc == tmp / "hello.txt.enc" and keyp == tmp / "hello.txt.key"
    assert enc.stat().st_size == 39
    assert client.decrypt_bytes(KEY, enc.read_bytes()) == HELLO
    assert keyp.read_bytes() == b"AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="
    assert client.read_b64_file(keyp) == KEY
    passed("op_encrypt: writes hello.txt.enc (39 bytes) and hello.txt.key; decrypts locally")

    client.op_encrypt(hello, KEY, tmp / "second.enc")
    assert (tmp / "second.enc").read_bytes() != enc.read_bytes()
    passed("op_encrypt: a fresh nonce for every file")

    refused(lambda: client.op_encrypt(over, KEY, tmp / "over.bin.enc"),
            "File to encrypt is larger than 1,048,548 bytes.")
    assert not (tmp / "over.bin.enc").exists()
    big_enc, _ = client.op_encrypt(exact, KEY, tmp / "exact.bin.enc")
    assert big_enc.stat().st_size == client.MAX_PAYLOAD
    passed("op_encrypt: 1,048,548 bytes allowed (gives 1 MiB), one more refused, nothing written")

    empty = tmp / "empty.bin"
    empty.write_bytes(b"")
    empty_enc, _ = client.op_encrypt(empty, KEY, tmp / "empty.bin.enc")
    assert empty_enc.stat().st_size == 28
    passed("op_encrypt: an empty file is allowed (28-byte .enc)")

    refused(lambda: client.op_encrypt(hello, KEY, tmp / "out.bin"),
            "The output file name must end in .enc.")
    passed("op_encrypt: an output name that does not end in .enc is refused")

    # ---- decrypt checks (all fail before any connection) -------------------
    refused(lambda: client.op_decrypt(*NET, hello, KEY), "Please pick a .enc file.")
    short = tmp / "short.enc"
    short.write_bytes(bytes(27))
    refused(lambda: client.op_decrypt(*NET, short, KEY),
            "Not a valid encrypted file (too short)")
    huge = tmp / "huge.enc"
    huge.write_bytes(bytes(client.MAX_PAYLOAD + 1))
    refused(lambda: client.op_decrypt(*NET, huge, KEY),
            "Encrypted file is larger than 1,048,576 bytes.")
    passed("op_decrypt: non-.enc, under 28 bytes and over 1 MiB are refused locally")

    # ---- HMAC files -------------------------------------------------------
    mac, hmac_path, hmackey_path = client.op_compute_hmac(hello, KEY)
    assert mac == MAC
    assert hmac_path == tmp / "hello.txt.hmac" and hmackey_path == tmp / "hello.txt.hmackey"
    assert client.read_b64_file(hmac_path) == MAC
    assert client.read_b64_file(hmackey_path) == KEY
    assert not hmac_path.read_bytes().endswith(b"\n")
    passed("op_compute_hmac: section 9 HMAC, .hmac and .hmackey written as base64")

    client.op_compute_hmac(empty, KEY)
    assert client.read_b64_file(tmp / "empty.bin.hmac").hex() == \
        "bb7a30c41398c718904264ee91bc9ea48a36493f9e5a5577f53a1408a6ffa5b3"
    passed("op_compute_hmac: an empty file is allowed")

    mib = tmp / "mib.bin"
    mib.write_bytes(bytes(client.MAX_PAYLOAD))
    client.op_compute_hmac(mib, KEY)                          # exactly 1 MiB is fine
    mib_plus = tmp / "mibplus.bin"
    mib_plus.write_bytes(bytes(client.MAX_PAYLOAD + 1))
    refused(lambda: client.op_compute_hmac(mib_plus, KEY), "File is larger than 1,048,576 bytes.")
    assert not (tmp / "mibplus.bin.hmac").exists()
    refused(lambda: client.op_verify(*NET, mib_plus, KEY, MAC),
            "File is larger than 1,048,576 bytes.")
    passed("op_compute_hmac / op_verify: over 1 MiB refused locally, 1 MiB allowed")

    # ---- original-file comparison -----------------------------------------
    work = tmp / "cmp"
    out = tmp / "cmp_out"
    work.mkdir()
    out.mkdir()
    enc_file = work / "note.txt.enc"
    enc_file.write_bytes(b"x")
    dec_file = client.write_decrypted(HELLO, enc_file, out)
    assert dec_file == out / "note.dec.txt" and dec_file.read_bytes() == HELLO

    result, msg = client.compare_with_original(enc_file, dec_file)
    assert (result, msg) == (None, "Original not found next to the .enc file, comparison skipped.")
    (out / "note.txt").write_bytes(HELLO)                     # original in the OUTPUT folder
    assert client.compare_with_original(enc_file, dec_file)[0] is None
    passed("comparison: original not found, and the output folder is not searched")

    (work / "note.txt").write_bytes(HELLO)
    assert client.compare_with_original(enc_file, dec_file) == (
        True, "Decrypted file matches the original byte for byte.")
    passed("comparison: matches the original")

    (work / "note.txt").write_bytes(b"hello worle")
    assert client.compare_with_original(enc_file, dec_file) == (
        False, "Decrypted file does NOT match the original.")
    (work / "note.txt").write_bytes(HELLO + b"!")
    assert client.compare_with_original(enc_file, dec_file)[0] is False
    passed("comparison: one changed byte, or a different length, does not match")

print("\nAll checks passed.")
