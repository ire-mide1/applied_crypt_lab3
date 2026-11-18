# Tests the client's network functions against fake_server.py on 127.0.0.1.
# Run: python crypto_client/test_fake_server.py

import client
import fake_server

HOST = "127.0.0.1"
USER = "student01"
KEY = bytes(range(32))
HELLO = b"hello world"
MAC = bytes.fromhex("585c65e6deb8b876ed74222c5964060e707192df8ce9b91b6198de173fbfff2e")


def passed(name):
    print("PASS  " + name)


server, port = fake_server.start_server(HOST, 0)
try:
    # get_key returns 32 bytes
    key = client.request_get_key(HOST, port, USER)
    assert isinstance(key, bytes) and len(key) == 32
    assert client.request_get_key(HOST, port, USER) != key     # fresh each time
    passed("get_key returns a 32-byte key (and a different one each call)")

    # encrypt locally, decrypt through the server
    blob = client.encrypt_bytes(key, HELLO)
    assert client.request_decrypt(HOST, port, USER, key, blob) == HELLO
    passed("encrypt then server decrypt round trip returns hello world")

    # verify_hmac: section 9 vector, then one changed byte
    assert client.custom_hmac(KEY, HELLO) == MAC
    assert client.request_verify(HOST, port, USER, KEY, MAC, HELLO) is True
    passed("verify_hmac gives VERIFIED for the section 9 vector")

    changed = bytes([HELLO[0] ^ 0x01]) + HELLO[1:]
    assert client.request_verify(HOST, port, USER, KEY, MAC, changed) is False
    passed("verify_hmac gives FAILED after one byte is changed (returns False, no exception)")

    # baduser: an error reply, raised as ServerError, never returned as FAILED
    for name, call in (
        ("get_key", lambda: client.request_get_key(HOST, port, "baduser")),
        ("verify_hmac", lambda: client.request_verify(HOST, port, "baduser", KEY, MAC, HELLO)),
    ):
        try:
            call()
        except client.ServerError as exc:
            assert exc.detail == "error processing request"
            assert not isinstance(exc, client.ClientError)
        else:
            raise AssertionError("baduser %s did not raise ServerError" % name)
    passed("baduser gets an error reply (ServerError), different from FAILED (False)")
finally:
    server.shutdown()
    server.server_close()

print("\nAll checks passed.")
