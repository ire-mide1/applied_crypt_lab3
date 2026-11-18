# Checks the client against the real server. Run it yourself:
#   python crypto_client/test_real_server.py
# Asks for the IP, port and username. They are kept only in memory for this
# run, are never saved, and are never printed.

import sys

import client

SECTION9_KEY = bytes(range(32))
HELLO = b"hello world"
SECTION9_MAC = bytes.fromhex(
    "585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e")

host = input("Server IP: ").strip()
port_text = input("Port [%d]: " % client.DEFAULT_PORT).strip() or str(client.DEFAULT_PORT)
username = input("Username: ").strip()

if not host:
    sys.exit("The server IP cannot be empty.")
if not (port_text.isdigit() and 1 <= int(port_text) <= 65535):
    sys.exit("The port must be a whole number from 1 to 65535.")
if not client.USERNAME_RE.fullmatch(username):
    sys.exit("The username must be 1-32 characters from A-Z a-z 0-9 _ . -")
port = int(port_text)

print()
failures = 0
state = {"key": None}


def step(name, check):
    """Run one check. check() returns None on success or a failure message."""
    global failures
    try:
        problem = check()
    except client.ServerError as exc:
        problem = "server returned an error reply: %s" % (exc.detail or "(no detail)")
    except client.ClientError as exc:
        problem = str(exc)
    except Exception as exc:                 # class name only, never its text
        problem = "unexpected error (%s)" % type(exc).__name__
    if problem is None:
        print("PASS  " + name)
    else:
        failures += 1
        print("FAIL  %s: %s" % (name, problem))


def check_get_key():
    key = client.request_get_key(host, port, username)
    if len(key) != 32:
        return "key is %d bytes, expected 32" % len(key)
    state["key"] = key


def check_round_trip():
    key = state["key"] or SECTION9_KEY       # step 1 key if we have one
    blob = client.encrypt_bytes(key, HELLO)
    result = client.request_decrypt(host, port, username, key, blob)
    if result != HELLO:
        return "decrypted bytes do not match hello world"


def check_verified():
    verified = client.request_verify(host, port, username, SECTION9_KEY, SECTION9_MAC, HELLO)
    if verified is not True:
        return "expected VERIFIED, server said FAILED"


def check_failed():
    changed = bytes([HELLO[0] ^ 0x01]) + HELLO[1:]
    verified = client.request_verify(host, port, username, SECTION9_KEY, SECTION9_MAC, changed)
    if verified is not False:
        return "expected FAILED, server said VERIFIED"


step("get_key returns a 32-byte key", check_get_key)
step("encrypt then server decrypt returns hello world", check_round_trip)
step("verify_hmac section 9 vector gives VERIFIED", check_verified)
step("verify_hmac with one changed byte gives FAILED", check_failed)

print()
print("All 4 steps passed." if failures == 0 else "%d of 4 steps failed." % failures)
sys.exit(1 if failures else 0)
