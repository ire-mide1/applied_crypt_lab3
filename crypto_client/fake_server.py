# Fake crypto server for testing the client on 127.0.0.1. Test use only.
# It reuses client.py framing and crypto, so it proves the client agrees with
# it, not that either is correct. Run alone: python fake_server.py [port]

import json
import os
import socketserver
import struct
import sys
import threading

import client

BAD_USERNAME = "baduser"       # test-only name the fake server always rejects
IDLE_TIMEOUT = 60


def build_reply(reply_type, **fields):
    """Frame a reply: 4-byte big-endian length, compact JSON header, payload."""
    payload = fields.pop("payload", b"")
    header = {"type": reply_type}
    header.update(fields)
    header["payload_len"] = len(payload)
    header_bytes = json.dumps(header, separators=(",", ":")).encode("utf-8")
    return struct.pack(">I", len(header_bytes)) + header_bytes + payload


def error_reply():
    return build_reply("error", detail="error processing request")


def handle_request(header, payload):
    """Return the reply bytes for one parsed request. Raises on a bad request."""
    username = header.get("username")
    if (not isinstance(username, str) or not client.USERNAME_RE.fullmatch(username)
            or username == BAD_USERNAME):
        raise client.ClientError("bad username")
    msg_type = header.get("type")
    if msg_type == "get_key":
        return build_reply("key_result", key=client.encode_b64(os.urandom(client.KEY_LEN)))
    key = client.decode_key_text(header.get("key"), "key")
    if msg_type == "decrypt":
        return build_reply("decrypt_result", payload=client.decrypt_bytes(key, payload))
    if msg_type == "verify_hmac":
        mac = client.decode_key_text(header.get("hmac"), "hmac")
        ok = client.custom_hmac(key, payload) == mac
        return build_reply("verify_result", result="VERIFIED" if ok else "FAILED")
    raise client.ClientError("unknown type")


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        self.request.settimeout(IDLE_TIMEOUT)
        try:
            header, payload = client.read_message(self.request)
            reply = handle_request(header, payload)
        except Exception:
            reply = error_reply()          # one generic error for every failure
        try:
            self.request.sendall(reply)
        except OSError:
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


def start_server(host="127.0.0.1", port=0):
    """Start in a background thread. Returns (server, actual port)."""
    server = Server((host, port), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, server.server_address[1]


if __name__ == "__main__":
    wanted = int(sys.argv[1]) if len(sys.argv) > 1 else client.DEFAULT_PORT
    srv, actual = start_server(port=wanted)
    print("Fake server on 127.0.0.1:%d (username %r is always rejected). Ctrl+C to stop."
          % (actual, BAD_USERNAME))
    try:
        threading.Event().wait()
    except KeyboardInterrupt:
        srv.shutdown()
